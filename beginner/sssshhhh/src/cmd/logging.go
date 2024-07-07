package main

import (
	"log"
	"os"
	"time"

	logger "github.com/charmbracelet/log"
)

var Log *logger.Logger

var l log.Logger

func StartLogger(logname string) error {
	var logfile *os.File
	var err error
	if logname != "" {
		logfile, err = os.OpenFile("filewatch.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return err
		}
	} else {
		logfile = os.Stdout
	}
	Log = logger.NewWithOptions(logfile, logger.Options{
		TimeFormat:      time.Kitchen,
		Level:           0,
		Prefix:          "",
		ReportTimestamp: true,
		ReportCaller:    false,
		CallerOffset:    1,
	})

	Log.SetFormatter(logger.TextFormatter)

	return nil
}
