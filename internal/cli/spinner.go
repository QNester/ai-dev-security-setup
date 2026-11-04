package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type spinner struct {
	writer  io.Writer
	color   bool
	enabled bool
	message atomic.Value
	done    chan struct{}
	stopped chan struct{}
	once    sync.Once
}

func (a *App) startSpinner(message string) *spinner {
	value := &spinner{
		writer:  a.Stderr,
		color:   a.colored(a.Stderr),
		done:    make(chan struct{}),
		stopped: make(chan struct{}),
	}
	value.message.Store(trimSpinnerMessage(message))
	value.enabled = a.spinnerEnabled(a.Stderr)
	if !value.enabled {
		close(value.stopped)
		return value
	}
	value.render()
	go value.run()
	return value
}

func (a *App) spinnerEnabled(writer io.Writer) bool {
	if a.forceSpinner {
		return true
	}
	if a.jsonErrors {
		return false
	}
	file, ok := writer.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (s *spinner) Set(message string) {
	if s == nil {
		return
	}
	s.message.Store(trimSpinnerMessage(message))
}

func (s *spinner) Stop() {
	if s == nil {
		return
	}
	s.once.Do(func() {
		if s.enabled {
			close(s.done)
			<-s.stopped
			fmt.Fprint(s.writer, "\r\033[2K")
		}
	})
}

func (s *spinner) run() {
	defer close(s.stopped)
	ticker := time.NewTicker(80 * time.Millisecond)
	defer ticker.Stop()
	frame := 0
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			frame = (frame + 1) % len(spinnerFrames)
			s.renderFrame(spinnerFrames[frame])
		}
	}
}

func (s *spinner) render() {
	s.renderFrame(spinnerFrames[0])
}

func (s *spinner) renderFrame(frame string) {
	message, _ := s.message.Load().(string)
	if message == "" {
		message = "working..."
	}
	if s.color {
		fmt.Fprintf(s.writer, "\r\033[2K%s%s%s %s%s%s", ansiCyan, frame, ansiReset, ansiDim, message, ansiReset)
		return
	}
	fmt.Fprintf(s.writer, "\r\033[2K%s %s", frame, message)
}

func trimSpinnerMessage(message string) string {
	message = strings.Join(strings.Fields(message), " ")
	const limit = 72
	runes := []rune(message)
	if len(runes) > limit {
		return string(runes[:limit-1]) + "…"
	}
	return message
}
