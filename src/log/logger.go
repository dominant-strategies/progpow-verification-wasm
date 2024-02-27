package log

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/natefinch/lumberjack"
	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

var Log Logger = Logger{logrus.New()}

func New(out_path string) Logger {
	logger := logrus.New()
	logger.SetOutput(&lumberjack.Logger{
		Filename:   out_path,
		MaxSize:    500, // megabytes
		MaxBackups: 3,
		MaxAge:     28, //days
	})
	return Logger{logger}
}

// Uses of the global logger will use the following static method.
func Trace(msg string, args ...interface{}) {
	Log.Trace(constructLogMessage(msg, args...))
}

// Individual logging instances will use the following method.
func (l Logger) Trace(msg string, args ...interface{}) {
	l.Logger.Trace(constructLogMessage(msg, args...))
}

func Debug(msg string, args ...interface{}) {
	Log.Debug(constructLogMessage(msg, args...))
}
func (l Logger) Debug(msg string, args ...interface{}) {
	l.Logger.Debug(constructLogMessage(msg, args...))
}

func Info(msg string, args ...interface{}) {
	Log.Info(constructLogMessage(msg, args...))
}
func (l Logger) Info(msg string, args ...interface{}) {
	l.Logger.Info(constructLogMessage(msg, args...))
}

func Warn(msg string, args ...interface{}) {
	Log.Warn(constructLogMessage(msg, args...))
}
func (l Logger) Warn(msg string, args ...interface{}) {
	l.Logger.Warn(constructLogMessage(msg, args...))
}

func Error(msg string, args ...interface{}) {
	Log.Error(constructLogMessage(msg, args...))
}
func (l Logger) Error(msg string, args ...interface{}) {
	l.Logger.Error(constructLogMessage(msg, args...))
}

func Fatal(msg string, args ...interface{}) {
	Log.Fatal(constructLogMessage(msg, args...))
}
func (l Logger) Fatal(msg string, args ...interface{}) {
	l.Logger.Fatal(constructLogMessage(msg, args...))
}

func Panic(msg string, args ...interface{}) {
	Log.Panic(constructLogMessage(msg, args...))
}
func (l Logger) Panic(msg string, args ...interface{}) {
	l.Logger.Panic(constructLogMessage(msg, args...))
}

func reportLineNumber(skiplevel int) string {
	if Logger.GetLevel(Log) < logrus.DebugLevel {
		return ""
	}
	_, file, line, ok := runtime.Caller(skiplevel + 1)
	fileAndDir := filepath.Join(filepath.Base(filepath.Dir(file)), filepath.Base(file))
	if !ok || fileAndDir == "log/logger.go" {
		return ""
	}
	return fmt.Sprintf("%s:%d", fileAndDir, line)
}

func constructLogMessage(msg string, fields ...interface{}) string {
	var pairs []string

	lineInfo := reportLineNumber(2)

	if len(fields) != 1 {
		// Sometimes we want to log a single string,
		if len(fields)%2 != 0 {
			fields = append(fields, "MISSING VALUE")
		}

		for i := 0; i < len(fields); i += 2 {
			key := fields[i]
			value := fields[i+1]
			pairs = append(pairs, fmt.Sprintf("%v=%v", key, value))
		}
	}

	if lineInfo != "" {
		return fmt.Sprintf("%-40s %-40s %s", lineInfo, msg, strings.Join(pairs, " "))
	} else {
		return fmt.Sprintf("%-40s %s", msg, strings.Join(pairs, " "))
	}
}
