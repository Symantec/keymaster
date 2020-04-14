package systeelogger

import (
	"fmt"
	"log/syslog"
)

const (
	priority = syslog.LOG_AUTHPRIV
	log_name = "keymaster"
)

type Logger struct {
	One *syslog.Writer
}

func New() *Logger {
	sysLog, err := syslog.New(priority, log_name)
	if err != nil {
		fmt.Print("System log failed")
	}
	return &Logger{sysLog}
}

func (l *Logger) Fatal(v ...interface{})                 {}
func (l *Logger) Fatalf(format string, v ...interface{}) {}
func (l *Logger) Fatalln(v ...interface{})               {}
func (l *Logger) Panic(v ...interface{})                 {}
func (l *Logger) Panicf(format string, v ...interface{}) {}
func (l *Logger) Panicln(v ...interface{})               {}
func (l *Logger) Print(v ...interface{}) {
	msg := fmt.Sprintln(v...)
	l.One.Notice(msg)
}
func (l *Logger) Printf(format string, v ...interface{}) {}
func (l *Logger) Println(v ...interface{})               {}
func (l *Logger) Close() {
	l.One.Close()
}
