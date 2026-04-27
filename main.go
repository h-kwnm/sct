package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
)

const version = "0.2.0"

func main() {
	// debug logging
	debug := flag.Bool("debug", false, "enable debug logging")
	flag.Parse()

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))

	args := flag.Args()
	if len(args) < 1 {
		fmt.Println("usage: sct <command> [options]")
		return
	}

	switch args[0] {
	case "logs":
		runLogs(args[1:])
		return
	case "checkpoint":
		runCheckpoint(args[1:])
		return
	case "data":
		runData(args[1:])
		return
	case "get-sct":
		runGetSct(args[1:])
		return
	case "audit":
		runAudit(args[1:])
		return
	case "audit-path":
		runAuditPath(args[1:])
		return
	case "version":
		fmt.Println(version)
		return
	default:
		fmt.Printf("unknown command: %s\n", args[0])
		return
	}
}
