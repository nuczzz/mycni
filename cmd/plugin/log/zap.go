package log

import (
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	logFileMaxSizeMB = 1024
)

func shortCallerWithClassFunctionEncoder(caller zapcore.EntryCaller, enc zapcore.PrimitiveArrayEncoder) {
	callerPath := caller.TrimmedPath()
	if f := runtime.FuncForPC(caller.PC); f != nil {
		name := f.Name()
		i := strings.LastIndex(name, "/")
		j := strings.Index(name[i+1:], ".")
		callerPath += " " + name[i+j+2:]
	}
	enc.AppendString(callerPath)
}

func timeEncoder(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
	enc.AppendString(t.Format("2006-01-02 15:04:05.000"))
}

func createZapLog(logFullName string, maxSize, maxAge, maxBackups int, compress bool, logLevel zapcore.LevelEnabler, callSkip int) *zap.SugaredLogger {
	if maxSize > logFileMaxSizeMB {
		maxSize = logFileMaxSizeMB
	}

	if maxAge < 0 {
		maxAge = 0
	}

	if maxBackups < 0 {
		maxBackups = 0
	}

	// 多个writer，加上stdout，在容器中可以直接logs看
	writers := []zapcore.WriteSyncer{
		zapcore.AddSync(&lumberjack.Logger{
			Filename: logFullName,
			//MaxSize:    maxSize, // default 100 megabytes
			MaxBackups: maxBackups,
			MaxAge:     maxAge, // days
			Compress:   compress,
		}),
		//zapcore.AddSync(os.Stdout),
	}

	cfg := zapcore.EncoderConfig{
		MessageKey:     "M",
		LevelKey:       "L",
		NameKey:        "N",
		TimeKey:        "T",
		CallerKey:      "C",
		StacktraceKey:  "S",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeTime:     timeEncoder, //zapcore.ISO8601TimeEncoder,
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   shortCallerWithClassFunctionEncoder, //zapcore.ShortCallerEncoder, //
		EncodeName:     zapcore.FullNameEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(cfg),
		zapcore.NewMultiWriteSyncer(writers...),
		logLevel,
	)

	logger := zap.New(core, zap.AddCaller(), zap.AddStacktrace(zap.DPanicLevel), zap.AddCallerSkip(callSkip), zap.Development())
	suger := logger.Sugar()
	return suger
}