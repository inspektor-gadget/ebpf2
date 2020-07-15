package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

const minimalSocketFilter = `__attribute__((section("socket"), used)) int main() { return 0; }`

func TestCompile(t *testing.T) {
	tmpFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	var obj, dep bytes.Buffer
	err := compile(compileArgs{
		cc:   "clang",
		file: tmpFile,
		out:  &obj,
		dep:  &dep,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	if obj.Len() == 0 {
		t.Error("Compilation returns an empty result")
	}

	if dep.Len() == 0 {
		t.Error("Compilation doesn't generate depinfo")
	}
}

func TestReproducibleCompile(t *testing.T) {
	aFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)
	bFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	var a, b bytes.Buffer
	err := compile(compileArgs{
		cc:   "clang",
		file: aFile,
		out:  &a,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	err = compile(compileArgs{
		cc:   "clang",
		file: bFile,
		out:  &b,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("Compiling the same file twice doesn't give the same result")
	}
}

func mustWriteTempFile(t *testing.T, name, contents string) string {
	t.Helper()

	tmp, err := ioutil.TempDir("", "bpf2go")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	tmpFile := filepath.Join(tmp, name)
	if err := ioutil.WriteFile(tmpFile, []byte(contents), 0660); err != nil {
		t.Fatal(err)
	}

	return tmpFile
}
