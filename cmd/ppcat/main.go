package main

import (
	"io"
	"log"
	"os"
	"strconv"
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
		Usage: "take <file...>",
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
	if err := cli.Run(commands, cli.Usage("prx", helpText, commands), nil); err != nil {
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

	line := Line(*csv)
	for {
		switch p, err := d.Decode(false); err {
		case nil:
			line.AppendTime(p.Timestamp(), rt.TimeFormat, linewriter.AlignCenter)
			line.AppendString(p.State.String(), 8, linewriter.AlignRight)
			line.AppendBytes(p.Code[:], 0, linewriter.Hex)
			line.AppendUint(uint64(p.Orbit), 8, linewriter.Hex|linewriter.WithZero)
			line.AppendString(p.Type.String(), 12, linewriter.AlignRight)
			line.AppendUint(uint64(p.Len), 8, linewriter.AlignRight)

			io.Copy(os.Stdout, line)
		case io.EOF:
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
	origin := cmd.Flag.String("p", "", "origin")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	dirs := make([]string, cmd.Flag.NArg()-1)
	for i := 1; i < cmd.Flag.NArg(); i++ {
		dirs[i] = cmd.Flag.Arg(i)
	}
	mr, err := rt.Browse(dirs, true)
	if err != nil {
		return err
	}
	defer mr.Close()

	o, err := strconv.ParseUint(*origin, 16, 8)
	if err != nil {
		return err
	}
	wc, err := os.Create(cmd.Flag.Arg(0))
	if err != nil {
		return err
	}
	defer wc.Close()

	d := pdh.NewDecoder(rt.NewReader(mr), pdh.WithOrigin(byte(o)))
	for {
		switch p, err := d.Decode(true); err {
		case nil:
			if buf, err := p.Marshal(); err == nil {
				if _, err := wc.Write(buf); err != nil {
					return err
				}
			}
		case io.EOF:
			return nil
		default:
			return err
		}
	}
}
