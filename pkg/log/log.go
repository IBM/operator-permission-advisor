/**
Copyright 2022 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package log

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"time"
)

var (
	infoLog  *log.Logger
	errorLog *log.Logger
)

func init() {
	infoLog = log.New(ioutil.Discard, "", 0)
	errorLog = log.New(ioutil.Discard, "", 0)
	infoLog.SetOutput(os.Stdout)
	errorLog.SetOutput(io.MultiWriter(os.Stdout, os.Stderr))
}

type OpaLogSeverity string

const (
	// used for logging to STDOUT only
	InfoSeverity OpaLogSeverity = "info"
	// used for logging to STDOUT and STDERR together
	ErrorSeverity OpaLogSeverity = "error"
)

type LogMessage struct {
	// LogMessage will hold information needed to JSON log to the user

	// list of key value pairs as a string to include in the message
	KeyValuePairs string `json:"keyValuePairs"`
	// the severity toggle for chosing the correct logger
	Severity OpaLogSeverity `json:"severity"`
	// the timestamp of the log generation
	Timestamp string `json:"timestamp"`
}

type LoggerStruct struct{}

type Logger interface {
	// Logger is the interface contract for a opa logger

	LogWithValues(OpaLogSeverity, ...interface{})
	Info(...interface{})
	Error(error)
	Plain(string)
}

// Plain takes a string and logs it without JSON to the screen
func (l *LoggerStruct) Plain(s string) {
	infoLog.Println(s)
}

// Info takes a key value pair interfaace array and logs it with the info logger
func (l *LoggerStruct) Info(keyValuePairs ...interface{}) {
	l.LogWithValues(InfoSeverity, keyValuePairs...)
}

// Error takes an error and logs it with the error logger
func (l *LoggerStruct) Error(e error) {
	l.LogWithValues(ErrorSeverity, "error", e)
}

// LogWithValues takes the severity logger key and the key value pair interface and logs to the user using
// the correct logging interface
func (l *LoggerStruct) LogWithValues(severity OpaLogSeverity, keyValuePairs ...interface{}) {
	if l == nil {
		panic("cannot log from a nil pointer")
	}
	var kv []string = []string{}
	for i := 0; i < len(keyValuePairs); i++ {
		if i+1 >= len(keyValuePairs) {
			break
		}

		key := keyValuePairs[i]
		value := keyValuePairs[i+1]

		kv = append(kv, fmt.Sprintf("%v=%v", key, value))
		i++
	}

	lm := &LogMessage{
		KeyValuePairs: strings.Join(kv, ","),
		Severity:      severity,
		Timestamp:     time.Now().Format(time.UnixDate),
	}

	toLog, err := json.Marshal(lm)
	if err != nil {
		panic(err)
	}

	switch severity {
	case InfoSeverity:
		infoLog.Println(string(toLog))
	case ErrorSeverity:
		errorLog.Println(string(toLog))
	default:
	}

}

var KLogger Logger = &LoggerStruct{}
