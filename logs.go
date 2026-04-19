package main

import (
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
)

func runLogs(args []string) {
	fs := flag.NewFlagSet("logs", flag.ExitOnError)
	refresh := fs.Bool("refresh", false, "re-fetch log list from Google")
	state := fs.String("state", "", "filter by state (usable, readonly, retired, ...)")
	fs.Parse(args)

	// load/fetch log list
	cache, err := loadLogCache()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load log list cache: %v\n", err)
		os.Exit(1)
	}

	if cache == nil || *refresh {
		logList, err := fetchLogList()
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch log list: %v\n", err)
			os.Exit(1)
		}
		cache, err = buildLogCache(logList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to build log list cache: %v\n", err)
			os.Exit(1)
		}
		if err := saveLogCache(cache); err != nil {
			fmt.Fprintf(os.Stderr, "failed to save log list cache: %v\n", err)
			os.Exit(1)
		}
	}

	// show log list
	logs := cache.Logs
	if *state != "" {
		filtered := logs[:0]
		for _, log := range logs {
			if string(log.State) == *state {
				filtered = append(filtered, log)
			}
		}
		logs = filtered
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tOPERATOR\tDESCRIPTION\tSTATE")
	for _, log := range logs {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n", log.Id, log.Operator, log.Description, log.State)
	}
	w.Flush()
}
