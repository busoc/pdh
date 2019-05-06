package main

import (
	"io"
	"log"
	"os"

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
	d := pdh.NewDecoder(rt.NewReader(mr))

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
}

func runCount(cmd *cli.Command, args []string) error {
	csv := cmd.Flag.Bool("c", false, "csv format")
	if err := cmd.Flag.Parse(args); err != nil {
		return err
	}
	mr, err := rt.Browse(cmd.Flag.Args(), true)
	if err != nil {
		return err
	}
	defer mr.Close()
	d := pdh.NewDecoder(rt.NewReader(mr))

	stats := make(map[key]rt.Coze)
	for {
		p, err := d.Decode(false)
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		k := key{
			Origin: p.Code[0],
			Code:   p.Code,
		}
		cz := stats[k]
		cz.Count++
		cz.Size += uint64(p.Len)

		cz.EndTime = p.Timestamp()
		if cz.StartTime.IsZero() {
			cz.StartTime = cz.EndTime
		}

		stats[k] = cz
	}
	line := Line(*csv)
	for k, cz := range stats {
		line.AppendUint(uint64(k.Origin), 2, linewriter.Hex|linewriter.WithZero)
		line.AppendBytes(k.Code[:], 12, linewriter.Hex)
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
	d := pdh.NewDecoder(rt.NewReader(mr))

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
