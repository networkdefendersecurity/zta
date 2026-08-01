package auditlog

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// pollInterval is how often View re-checks the log for appended lines while
// following. Polling (rather than fsnotify) keeps the binary dependency-free.
const pollInterval = time.Second

// ViewOptions configures a `zta log` read.
type ViewOptions struct {
	Root        string // project root used to locate the default log
	Follow      bool   // keep tailing for new decisions (tail -f style)
	Lines       int    // trailing matching decisions to show first (0 = all)
	OnlyBlocked bool   // show only blocks
	OnlyAllowed bool   // show only allows
	JSON        bool   // emit raw JSONL instead of the human-readable form
}

// View prints logged decisions to w. With Follow set it prints the trailing
// backlog and then blocks, emitting new decisions as they are appended, until
// the process is interrupted.
func View(w io.Writer, opts ViewOptions) error {
	if opts.OnlyBlocked && opts.OnlyAllowed {
		return errors.New("use only one of --blocked / --allowed")
	}
	path := Path(opts.Root)
	if path == "" {
		return errors.New("audit logging is disabled (ZTA_LOG=off); nothing to show")
	}

	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		emitTail(w, data, opts)
	case os.IsNotExist(err):
		if !opts.Follow {
			fmt.Fprintf(w, "no audit log yet at %s\n", path)
			return nil
		}
		// fall through to the follow loop and wait for it to appear
	default:
		return err
	}
	if !opts.Follow {
		return nil
	}

	offset := int64(len(data)) // bytes already emitted as backlog
	for {
		time.Sleep(pollInterval)
		fi, err := os.Stat(path)
		if err != nil {
			continue // not created yet, or transiently unavailable
		}
		size := fi.Size()
		if size < offset {
			offset = 0 // truncated or rotated; re-read from the top
		}
		if size == offset {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			f.Close()
			continue
		}
		chunk, _ := io.ReadAll(f)
		f.Close()
		offset += int64(emitChunk(w, chunk, opts))
	}
}

// emitTail prints the last opts.Lines matching records from a full log buffer.
func emitTail(w io.Writer, data []byte, opts ViewOptions) {
	var matched [][]byte
	for _, line := range bytes.Split(data, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if rec, ok := decode(line); ok && matches(rec, opts) {
			matched = append(matched, line)
		}
	}
	start := 0
	if opts.Lines > 0 && len(matched) > opts.Lines {
		start = len(matched) - opts.Lines
	}
	for _, line := range matched[start:] {
		emit(w, line, opts)
	}
}

// emitChunk emits every complete (newline-terminated) line in chunk and returns
// the number of bytes consumed, so a trailing partial write is re-read later.
func emitChunk(w io.Writer, chunk []byte, opts ViewOptions) int {
	last := bytes.LastIndexByte(chunk, '\n')
	if last < 0 {
		return 0
	}
	for _, line := range bytes.Split(chunk[:last+1], []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		emit(w, line, opts)
	}
	return last + 1
}

// emit writes one record line if it matches the filter, in the chosen format.
func emit(w io.Writer, line []byte, opts ViewOptions) {
	rec, ok := decode(line)
	if !ok || !matches(rec, opts) {
		return
	}
	if opts.JSON {
		w.Write(line)
		w.Write([]byte{'\n'})
		return
	}
	fmt.Fprintln(w, human(rec))
}

func decode(line []byte) (Record, bool) {
	var rec Record
	if json.Unmarshal(line, &rec) != nil {
		return rec, false
	}
	return rec, true
}

func matches(rec Record, opts ViewOptions) bool {
	if opts.OnlyBlocked && rec.Decision != "block" {
		return false
	}
	if opts.OnlyAllowed && rec.Decision != "allow" {
		return false
	}
	return true
}

// human renders a record as a single aligned line:
//
//	<time>  BLOCK  exec        rm -rf /            [AC-01/destructive-delete]
func human(rec Record) string {
	target := rec.Command
	for _, alt := range []string{rec.Path, rec.URL, rec.Tool} {
		if target == "" {
			target = alt
		}
	}
	line := fmt.Sprintf("%s  %-5s  %-10s  %s", rec.Time, strings.ToUpper(rec.Decision), rec.Action, target)
	if rec.Decision == "block" && (rec.Control != "" || rec.Rule != "") {
		line += fmt.Sprintf("  [%s/%s]", rec.Control, rec.Rule)
	}
	return line
}
