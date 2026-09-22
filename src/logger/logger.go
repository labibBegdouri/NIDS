package logger

import (
	"bufio"
	"fmt"
	"os"
	"time"
)

type Logger struct {
	logFile *os.File
	writer  *bufio.Writer
}

func New(path string) (*Logger, error) {
	file, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	return &Logger{logFile: file, writer: bufio.NewWriter(file)}, nil
}

func (logger *Logger) Write(message, ip string) {
	fmt.Fprintf(logger.writer, "[%s] %s IP %s\n", time.Now().Format("Mon Jan 02 15:04:05 2006"), message, ip)
}

func (logger *Logger) Flush() error { return logger.writer.Flush() }

func (logger *Logger) Close() error {
	if err := logger.Flush(); err != nil {
		_ = logger.logFile.Close()
		return err
	}
	return logger.logFile.Close()
}
