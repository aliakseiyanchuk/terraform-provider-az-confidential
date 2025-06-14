package core

//
//import (
//	"bytes"
//	"fmt"
//	"github.com/stretchr/testify/assert"
//	"io"
//	"os"
//	"path/filepath"
//	"testing"
//)
//
//func TestInsecureOpen(t *testing.T) {
//	name := "a/../../../secret.txt"
//	txt, err := os.ReadFile(name)
//	assert.Nil(t, err)
//	fmt.Println(string(txt))
//}
//
//func TestOpenWithEscape(t *testing.T) {
//	name := "a/../../../secret.txt"
//	fmt.Printf("IsLocal = %t\n", filepath.IsLocal(name))
//
//	localize, locErr := filepath.Localize(name)
//	assert.Nil(t, locErr)
//	if locErr != nil {
//		return
//	}
//
//	fmt.Printf("Localized path = %s\n", localize)
//
//	txt, err := os.ReadFile(name)
//	assert.Nil(t, err)
//	fmt.Println(string(txt))
//}
//
//func TestOpenViaSymlink(t *testing.T) {
//	name := "blnk/secret.txt"
//	fmt.Printf("IsLocal = %t\n", filepath.IsLocal(name))
//
//	localize, locErr := filepath.Localize(name)
//	assert.Nil(t, locErr)
//	if locErr != nil {
//		return
//	}
//
//	fmt.Printf("Localized path = %s\n", localize)
//
//	txt, err := os.ReadFile(name)
//	assert.Nil(t, err)
//	fmt.Println(string(txt))
//}
//
//func TestOpenWithRootWithEscape(t *testing.T) {
//	root, rootInitErr := os.OpenRoot("..")
//	assert.Nil(t, rootInitErr)
//	defer root.Close()
//
//	f, err := root.Open("../secret.txt")
//	assert.Nil(t, err)
//	if err != nil {
//		fmt.Println(err.Error())
//		return
//	}
//
//	defer f.Close()
//	fileContents := readFileFully(f)
//	fmt.Println(string(fileContents.Bytes()))
//}
//
//func TestOpenWithRootWithEscapeViaSymlink(t *testing.T) {
//	root, rootInitErr := os.OpenRoot("..")
//	assert.Nil(t, rootInitErr)
//	defer root.Close()
//
//	f, err := root.Open("blnk/secret.txt")
//	assert.Nil(t, err)
//	if err != nil {
//		fmt.Println(err.Error())
//		return
//	}
//
//	defer f.Close()
//	fileContents := readFileFully(f)
//	fmt.Println(string(fileContents.Bytes()))
//}
//
//func readFileFully(f *os.File) bytes.Buffer {
//	var fileContents bytes.Buffer
//
//	buf := make([]byte, 1024)
//	for {
//		n, err := f.Read(buf)
//		if err == io.EOF {
//			break
//		} else {
//			fileContents.Write(buf[:n])
//		}
//	}
//	return fileContents
//}
