package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

func ReadInput(prompt, fn string, base64Decode bool, multiline bool) ([]byte, error) {
	var outputBytes []byte
	if len(fn) > 0 {
		if file, err := os.ReadFile(fn); err != nil {
			return nil, err
		} else {
			outputBytes = file
		}
	}

	stdinStat, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}

	// The input file is read from a
	if (stdinStat.Mode() & os.ModeNamedPipe) != 0 {
		if stdinBytes, stdinErr := io.ReadAll(os.Stdin); stdinErr != nil {
			return nil, stdinErr
		} else {
			outputBytes = stdinBytes
		}
	} else if (stdinStat.Mode() & os.ModeCharDevice) != 0 {
		fmt.Println(prompt)

		outBuf := bytes.Buffer{}
		reader := bufio.NewReader(os.Stdin)
		readInput := true

		for readInput {
			if str, readErr := reader.ReadString('\n'); readErr != nil {
				return nil, readErr
			} else {
				str = strings.TrimSpace(str)
				if len(str) > 0 {
					outBuf.WriteString(str)

					if multiline {
						outBuf.WriteString("\n")
					}
				}

				readInput = multiline && len(str) > 0
			}
		}

		outputBytes = outBuf.Bytes()
	}

	if outputBytes == nil {
		return nil, errors.New("no input file found")
	} else if base64Decode {
		dst := make([]byte, base64.StdEncoding.DecodedLen(len(outputBytes)))
		n, b64Err := base64.StdEncoding.Decode(dst, outputBytes)
		if b64Err != nil {
			return nil, b64Err
		}
		outputBytes = dst[:n]
	}

	return outputBytes, nil
}
