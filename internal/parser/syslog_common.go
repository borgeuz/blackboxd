package parser

// Shared helpers for the RFC 3164 and RFC 5424 parsers.

// maxPriority = facility 23 (local7) * 8 + severity 7 (debug).
const maxPriority = 191

// parsePriorityField consumes "<NNN>" at the start of s. PRI is 1-3
// ASCII digits between angle brackets per RFC 3164 §4.1.1 / RFC 5424
// §6.2.1; anything else is rejected.
func parsePriorityField(s string) (rest string, facility, severity int, err error) {
	if len(s) < 3 || s[0] != '<' {
		return s, 0, 0, ErrInvalidFormat
	}
	end := -1
	prio := 0
	for i := 1; i < len(s) && i <= 4; i++ {
		c := s[i]
		if c == '>' {
			end = i
			break
		}
		if c < '0' || c > '9' {
			return s, 0, 0, ErrInvalidPriority
		}
		prio = prio*10 + int(c-'0')
	}
	if end == -1 || end == 1 {
		return s, 0, 0, ErrInvalidPriority
	}
	if prio > maxPriority {
		return s, 0, 0, ErrInvalidPriority
	}
	return s[end+1:], prio / 8, prio % 8, nil
}

// severityToLevel maps 0-7 to Level. Out-of-range falls back to
// Warning so a corrupt PRI byte never yields "unknown" in the JSON.
func severityToLevel(severity int) Level {
	switch severity {
	case 0:
		return LevelEmergency
	case 1:
		return LevelAlert
	case 2:
		return LevelCritical
	case 3:
		return LevelError
	case 4:
		return LevelWarning
	case 5:
		return LevelNotice
	case 6:
		return LevelInfo
	case 7:
		return LevelDebug
	default:
		return LevelWarning
	}
}

// trimTrailingNewline strips one \n or \r\n. Trailing whitespace
// inside the message itself is preserved.
func trimTrailingNewline(line string) string {
	n := len(line)
	if n > 0 && line[n-1] == '\n' {
		line = line[:n-1]
		n--
	}
	if n > 0 && line[n-1] == '\r' {
		line = line[:n-1]
	}
	return line
}
