package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/busoc/pdh"
	"github.com/busoc/rt"
	"github.com/midbel/cli"
	"github.com/midbel/linewriter"
)

var commands = []*cli.Command{
	{
		Usage: "list [-i] [-g] <file...>",
		Short: "",
		Run:   runList,
	},
	{
		Usage: "diff [-i] [-g] <file...>",
		Short: "",
		Run:   runDiff,
	},
	{
		Usage: "count [-g] <file...>",
		Short: "",
		Run:   runCount,
	},
	{
		Usage: "take [-d interval] [-c catalog] [-n name] <pattern> <file...>",
		Short: "",
		Run:   runTake,
	},
}

const helpText = `{{.Name}} scan the HRDP archive to consolidate the USOC HRDP archive

Usage:

  {{.Name}} command [options] <arguments>

Available commands:

{{range .Commands}}{{if .Runnable}}{{printf "  %-12s %s" .String .Short}}{{if .Alias}} (alias: {{ join .Alias ", "}}){{end}}{{end}}
{{end}}
Use {{.Name}} [command] -h for more information about its usage.
`

func main() {
	defer func() {
		if err := recover(); err != nil {
			log.Fatalf("unexpected error: %s", err)
		}
	}()
	log.SetFlags(0)
	if err := cli.Run(commands, cli.Usage("ppcat", helpText, commands), nil); err != nil {
		log.Fatalln(err)
	}
}

func Line(csv bool) *linewriter.Writer {
	var options []linewriter.Option
	if csv {
		options = append(options, linewriter.AsCSV(true))
	} else {
		options = []linewriter.Option{
			linewriter.WithPadding([]byte(" ")),
			linewriter.WithSeparator([]byte("|")),
		}
	}
	return linewriter.NewWriter(1024, options...)
}

func runList(cmd *cli.Command, args []string) error {
	quiet := cmd.Flag.Bool("q", false, "quiet")
	hrdp := cmd.Flag.Bool("a", false, "hrdp")
	csv := cmd.Flag.Bool("c", false, "csv format")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pdh.NewDecoder(rt.NewReader(mr), nil)

	var base uint16
	if *hrdp {
		base = pdh.UMIHeaderLen
	}

	line := Line(*csv)
	var z rt.Coze
	for {
		switch p, err := d.Decode(false); err {
		case nil:
			if !*quiet {
				line.AppendTime(p.Timestamp(), rt.TimeFormat, linewriter.AlignCenter)
				line.AppendString(p.State.String(), 8, linewriter.AlignRight)
				line.AppendBytes(p.Code[:], 0, linewriter.Hex)
				line.AppendUint(uint64(p.Orbit), 8, linewriter.Hex|linewriter.WithZero)
				line.AppendString(p.Type.String(), 12, linewriter.AlignRight)
				line.AppendUint(uint64(p.Len+base), 8, linewriter.AlignRight)

				io.Copy(os.Stdout, line)
			}
			z.EndTime = p.Timestamp()
			if z.StartTime.IsZero() {
				z.StartTime = z.EndTime
			}
			z.Size += uint64(p.Len)
			z.Count++
		case io.EOF:
			// fmt.Printf("%d packets (%d)\n", z.Count, z.Size>>20)
			return nil
		default:
			return err
		}
	}
	return nil
}

type key struct {
	Origin byte
	Code   [pdh.UMICodeLen]byte
	time.Time
}

func runCount(cmd *cli.Command, args []string) error {
	csv := cmd.Flag.Bool("c", false, "csv format")
	interval := cmd.Flag.Duration("i", 0, "interval")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pdh.NewDecoder(rt.NewReader(mr), nil)

	line := Line(*csv)
	for cz := range countPackets(d, *interval) {
		line.AppendUint(uint64(cz.origin.Origin), 2, linewriter.Hex|linewriter.WithZero)
		line.AppendBytes(cz.origin.Code[:], 12, linewriter.Hex)
		line.AppendUint(cz.Count, 8, linewriter.AlignRight)
		if *csv {
			line.AppendUint(cz.Size, 8, linewriter.AlignRight)
		} else {
			line.AppendSize(int64(cz.Size), 8, linewriter.AlignRight)
		}
		line.AppendTime(cz.StartTime, rt.TimeFormat, linewriter.AlignRight)
		line.AppendTime(cz.EndTime, rt.TimeFormat, linewriter.AlignRight)
		io.Copy(os.Stdout, line)
	}

	return nil
}

func runDiff(cmd *cli.Command, args []string) error {
	csv := cmd.Flag.Bool("c", false, "csv format")
	duration := cmd.Flag.Duration("d", 0, "minimum duration between two packets")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pdh.NewDecoder(rt.NewReader(mr), nil)

	line := Line(*csv)

	stats := make(map[[pdh.UMICodeLen]byte]pdh.Packet)
	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if other, ok := stats[p.Code]; ok {
			f, t := other.Timestamp(), p.Timestamp()
			if delta := t.Sub(f); *duration <= 0 || delta >= *duration {
				line.AppendBytes(p.Code[:], 0, linewriter.Hex)
				line.AppendTime(f, rt.TimeFormat, linewriter.AlignRight)
				line.AppendTime(t, rt.TimeFormat, linewriter.AlignRight)
				line.AppendDuration(delta, 16, linewriter.AlignLeft)

				io.Copy(os.Stdout, line)
			}
		}
		stats[p.Code] = p
	}
	return nil
}

func byKey(p pdh.Packet, d time.Duration) key {
	k := key{
		Origin: p.Code[0],
		Code:   p.Code,
	}
	if d > 0 {
		k.Time = p.Timestamp().Truncate(d)
	}
	return k
}

type coze struct {
	rt.Coze
	origin key
}

func countPackets(d *pdh.Decoder, i time.Duration) <-chan coze {
	q := make(chan coze)
	go func() {
		defer close(q)

		stats := make(map[key]rt.Coze)
		keys := make(map[key]time.Time)
		for {
			p, err := d.Decode(false)
			if err != nil {
				if err == io.EOF {
					break
				}
				return
			}
			k := byKey(p, i)

			cz, ok := stats[k]
			if !ok {
				tmp := byKey(p, 0)
				tmp.Time = keys[tmp]
				if !tmp.Time.IsZero() {
					q <- coze{Coze: stats[tmp], origin: tmp}
					delete(stats, tmp)

					tmp.Time = time.Time{}
				}
				keys[tmp] = k.Time
			}

			cz.Count++
			cz.Size += uint64(p.Len)
			cz.EndTime = p.Timestamp()
			if cz.StartTime.IsZero() {
				cz.StartTime = cz.EndTime
			}
			stats[k] = cz
		}
		for k, cz := range stats {
			q <- coze{Coze: cz, origin: k}
		}
	}()
	return q
}

func runTake(cmd *cli.Command, args []string) error {
	return fmt.Errorf("not yet implemented")
}

type catalog struct {
	codes [][]byte
	file  string
}

func (c *catalog) Set(v string) error {

	var rs io.Reader
	if f, e := os.Open(v); e == nil {
		defer f.Close()
		c.file = v
		rs = f
	} else {
		rs = strings.NewReader(v)
	}

	var (
		err  error
		scan = bufio.NewScanner(rs)
	)
	for lino := 1; scan.Scan() && err == nil; lino++ {
		code := scan.Text()
		if len(code) == 0 {
			continue
		}
		if xs, e := decodeCode(code); e == nil {
			c.codes = append(c.codes, xs)
		} else {
			err = fmt.Errorf("%d: %s", lino, e)
		}
	}
	if err != nil {
		return err
	}
	return scan.Err()
}

func (c *catalog) String() string {
	str := strings.TrimSuffix(filepath.Base(c.file), filepath.Ext(c.file))
	if str == "" {
		str = "catalog"
	}
	return str
}

func (c *catalog) Codes() [][]byte {
	return c.codes
}

func decodeCode(v string) ([]byte, error) {
	if len(v) != 12 {
		return nil, fmt.Errorf("%s: invalid code length (should have 12 characters)", v)
	}
	return hex.DecodeString(v)
}
