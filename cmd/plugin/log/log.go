package log

import (
	"fmt"
	"log"
	"path"
	"runtime"
	"sync"

	"go.uber.org/zap"
)

var (
	logger   *zap.SugaredLogger
	initOnce sync.Once
)

// InitZapLog 初始化日志配置
func InitZapLog(logFile string) {
	if logFile == "" {
		// 如果日志文件为空，不初始化zap log对象
		log.Println("logFile is null, do not init zap log")
		return
	}

	initOnce.Do(func() {
		logger = createZapLog(logFile, 100, 7, 7, true, zap.DebugLevel, 1)
	})
}

func Debugf(template string, args ...interface{}) {
	if logger != nil {
		logger.Debugf(template, args...)
	} else {
		_, file, line, _ := runtime.Caller(1)
		prefix := fmt.Sprintf("%v:%v: ", path.Base(file), line)
		log.Printf(prefix+template, args...)
	}
}
