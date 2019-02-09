// Copyright 2013 the Go ClamAV authors
// Use of this source code is governed by a
// license that can be found in the LICENSE file.

package clamav

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

var stdopts = &ScanOptions{
	General: ScanGeneralAllmatches,
	Parse:   0xFFFF,
}

func TestRetflevel(t *testing.T) {
	s := Retflevel()
	if s < 66 {
		t.Errorf("Retflevel (%d < 66, earliest tested)", s)
	}
}

func TestRetver(t *testing.T) {
	s := Retver()
	if s == "" {
		t.Errorf("Retver: nil")
	}
}

var StrErrorTests = []struct {
	num ErrorCode
	out string
}{
	{Success, "No viruses detected"},
	{Virus, "Virus(es) detected"},
	{Enullarg, "Null argument passed to function"},
	{Earg, "Invalid argument passed to function"},
	{Emalfdb, "Malformed database"},
	{Ecvd, "Broken or not a CVD file"},
	{Everify, "Can't verify database integrity"},
	{Eunpack, "Can't unpack some data"},
	{Eopen, "Can't open file or directory"},
	{Ecreat, "Can't create new file"},
	{Eunlink, "Can't unlink file"},
	{Estat, "Can't get file status"},
	{Eread, "Can't read file"},
	{Eseek, "Can't set file offset"},
	{Ewrite, "Can't write to file"},
	{Edup, "Can't duplicate file descriptor"},
	{Eacces, "Can't access file"},
	{Etmpfile, "Can't create temporary file"},
	{Etmpdir, "Can't create temporary directory"},
	{Emap, "Can't map file into memory"},
	{Emem, "Can't allocate memory"},
	{Etimeout, "Time limit reached"},
	{Break, "Unknown error code"},
	{Emaxrec, "CL_EMAXREC"},
	{Emaxsize, "CL_EMAXSIZE"},
	{Emaxfiles, "CL_EMAXFILES"},
	{Eformat, "CL_EFORMAT: Bad format or broken data"},
	//{Eparse, "Can't parse data"},	// when 0.98 is released
	{Ebytecode, "Error during bytecode execution"},
	{EbytecodeTestfail, "Failure in bytecode testmode"},
	{Elock, "Mutex lock failed"},
	{Ebusy, "Scanner still active"},
	{Estate, "Bad state (engine not initialized, or already initialized)"},
	{ELast, "Unknown error code"},
	{ELast + 1, "Unknown error code"},
	{1<<8 - 1, "Unknown error code"},
	{1<<16 - 1, "Unknown error code"},
	{1<<32 - 1, "Unknown error code"},
}

func TestStrError(t *testing.T) {
	for _, tt := range StrErrorTests {
		s := StrError(tt.num)
		if s != tt.out {
			t.Errorf("StrError: %d = %q, want %q", tt.num, s, tt.out)
		}
	}
}

func BenchmarkStrError(b *testing.B) {
	for i := 0; i < b.N; i++ {
		StrError(StrErrorTests[0].num)
	}
}

func TestDBDir(t *testing.T) {
	s := DBDir()
	if s == "" {
		t.Errorf("DBDir: nil")
	}
}

var CountSigsTests = []struct {
	path string
	want uint
}{
	{".", 0},
	{"testdata", 0},
	{DBDir(), 0},
}

func TestCountSigs(t *testing.T) {
	for _, v := range CountSigsTests {
		cnt, err := CountSigs(v.path, CountSigsAll)
		if err != nil {
			t.Errorf("CountSigs: %d, want %d in %s (%v)", cnt, v.want, v.path, err)
		}
	}
}

var numTypes = []struct {
	f                   EngineField
	isro, can0, is32bit bool
}{
	{EngineMaxScansize, false, true, false},
	{EngineMaxFilesize, false, true, false},
	{EngineMaxRecursion, false, false, true},
	{EngineMaxFiles, false, true, true},
	{EngineMinCcCount, false, true, true},
	{EngineMinSsnCount, false, true, true},
	/* char * */
	{EngineDbOptions, true, true, true}, // read-only
	{EngineDbVersion, true, true, true}, // read-only
	{EngineAcOnly, false, true, true},
	{EngineAcMindepth, false, true, true},
	{EngineAcMaxdepth, false, true, true},
	/* char * */
	{EngineKeeptmp, false, true, true},
	{EngineBytecodeSecurity, false, true, true},
	{EngineBytecodeTimeout, false, true, true},
	{EngineBytecodeMode, false, true, true},
}

var NumTests = []struct {
	num, want uint64
}{
	{0, 0},
	{1, 1},
	{2, 2},
	{1 << 6, 1 << 6},
	{1<<6 - 1, 1<<6 - 1},
	{1 << 16, 1 << 16},
	{1<<16 - 1, 1<<16 - 1},
	{1<<16 + 1, 1<<16 + 1},
	{1<<32 - 1, 1<<32 - 1},
	{1 << 32, 1 << 32},
	{1<<32 + 1, 1<<32 + 1},
	{1<<48 - 1, 1<<48 - 1},
	{1 << 48, 1 << 48},
	{1<<48 + 1, 1<<48 + 1},
	{1<<64 - 1, 1<<64 - 1},
}

/*
	// Read-only (but no docs!?)
*/

func TestGetSetNum(tt *testing.T) {
	eng := New()
	defer eng.Free()

	for _, t := range numTypes {
		for _, v := range NumTests {
			if !t.isro {
				if t.is32bit && v.num > 1<<32-1 {
					continue
				}
				if !t.can0 && v.num == 0 {
					continue
				}
				err := eng.SetNum(t.f, v.num)
				if err != nil {
					tt.Errorf("SetNum: field: %d (%d) %v", t.f, v.num, err)
				}
			}
			n, err := eng.GetNum(t.f)
			if err != nil {
				tt.Errorf("GetNum: (%d) %d: %v", t.f, v.num, err)
			}
			if t.isro {
				// blergh
				continue
			}
			if n != v.want {
				tt.Errorf("GetNum: (%d) %d want %d", t.f, n, v.want)
			}
		}
	}
	return
}

var stringTypes = []EngineField{
	EnginePuaCategories,
	EngineTmpdir,
}

var StringTests = []struct {
	set, want string
	match     bool
}{
	{"", "", true},
	{"abc", "abc", true},
	{"ABcd", "ABcd", true},
	{"123abc", "123abc", true},
	{"αβδ", "αβδ", true},
	{"ΑΒΔ", "ΑΒΔ", true},
}

func TestGetSetString(tt *testing.T) {
	eng := New()
	defer eng.Free()

	for _, t := range stringTypes {
		for _, v := range StringTests {
			err := eng.SetString(t, v.set)
			if err != nil {
				tt.Errorf("SetString: field: %d (%s) %v", t, v.set, err)
			}
			n, err := eng.GetString(t)
			if err != nil {
				tt.Errorf("GetString: (%d) %v: %v", t, v.set, err)
			}
			if v.match && n != v.want {
				tt.Errorf("GetString: (%d) %v want %v", t, n, v.want)
			}
		}
	}
}

var StringSizeTests = []int{
	32, 64, 128, 256, 512, 1024, 2048, 8192, 16384, 32768,
}

func test1(tt *testing.T, eng *Engine, fld EngineField, s string) {
	err := eng.SetString(fld, s)
	if err != nil {
		tt.Errorf("SetString: field: %d (%s) %v", fld, s, err)
	}
	ns, err := eng.GetString(fld)
	if err != nil {
		tt.Errorf("GetString: (%d) %s: %v", fld, ns, err)
	}
	if s != ns {
		tt.Errorf("GetString: (%d) %s want %v", fld, s, ns)
	}
}

func TestGetSetStringSize(t *testing.T) {
	eng := New()
	defer eng.Free()

	for _, fld := range stringTypes {
		for _, v := range StringSizeTests {
			test1(t, eng, fld, strings.Repeat("a", v-1))
			test1(t, eng, fld, strings.Repeat("a", v))
			test1(t, eng, fld, strings.Repeat("a", v+1))
		}
	}
}

func TestNewFree(t *testing.T) {
	eng := New()
	if eng == nil {
		t.Fatalf("New: nil engine")
	}
	err := ErrorCode(eng.Free())
	if err != Success {
		t.Fatalf("Free: %v", err)
	}
}

func TestSettings(t *testing.T) {
	eng := New()
	defer eng.Free()

	s := eng.CopySettings()
	if s == nil {
		t.Fatalf("CopySettings: nil settings after CopySettings")
	}
	if err := eng.ApplySettings(s); err != nil {
		t.Fatalf("ApplySettings: %v", err)
	}
	if err := FreeSettings(s); err != nil {
		t.Fatalf("FreeSettings: %v", err)
	}
}

func TestCompile(t *testing.T) {
	eng := New()
	defer eng.Free()
	if err := eng.Compile(); err != nil {
		t.Fatalf("Compile: %v", err)
	}
}

func TestAddref(t *testing.T) {
	eng := New()
	defer eng.Free()
	if err := eng.Addref(); err != nil {
		t.Fatalf("Addref: %v", err)
	}
}

var scanFiles = []struct {
	dir, file, name string
	scan            uint
}{
	{"testdata", "clam-aspack.exe", "Clamav.Test.File-6", 20},
	{"testdata", "clam-fsg.exe", "Clamav.Test.File-6", 4},
	{"testdata", "clam-mew.exe", "Clamav.Test.File-6", 20},
	{"testdata", "clam-nsis.exe", "Clamav.Test.File-6", 48},
	{"testdata", "clam-pespin.exe", "Clamav.Test.File-6", 20},
	{"testdata", "clam-petite.exe", "Clamav.Test.File-6", 8},
	{"testdata", "clam-upack.exe", "Clamav.Test.File-6", 16},
	{"testdata", "clam-upx.exe", "Clamav.Test.File-6", 20},
	{"testdata", "clam-v2.rar", "Clamav.Test.File-6", 0},
	{"testdata", "clam-v3.rar", "Clamav.Test.File-6", 0},
	{"testdata", "clam-wwpack.exe", "Clamav.Test.File-6", 24},
	{"testdata", "clam-yc.exe", "Clamav.Test.File-6", 24},
	{"testdata", "clam.7z", "Clamav.Test.File-6", 0},
	{"testdata", "clam.arj", "Clamav.Test.File-6", 0},
	{"testdata", "clam.bin-be.cpio", "Clamav.Test.File-6", 0},
	{"testdata", "clam.bin-le.cpio", "Clamav.Test.File-6", 0},
	{"testdata", "clam.bz2.zip", "Clamav.Test.File-6", 0},
	{"testdata", "clam.cab", "Clamav.Test.File-6", 0},
	{"testdata", "clam.chm", "Clamav.Test.File-6", 4},
	{"testdata", "clam.d64.zip", "Clamav.Test.File-6", 0},
	{"testdata", "clam.ea05.exe", "Clamav.Test.File-6", 232},
	{"testdata", "clam.ea06.exe", "Clamav.Test.File-6", 268},
	{"testdata", "clam.exe", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.binhex", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.bz2", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.html", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.mbox.base64", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.mbox.uu", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.rtf", "Clamav.Test.File-6", 0},
	{"testdata", "clam.exe.szdd", "Clamav.Test.File-6", 0},
	{"testdata", "clam.impl.zip", "Clamav.Test.File-6", 0},
	{"testdata", "clam.iso", "Clamav.Test.File-6", 352},
	{"testdata", "clam.mail", "Clamav.Test.File-6", 0},
	{"testdata", "clam.newc.cpio", "Clamav.Test.File-6", 0},
	{"testdata", "clam.odc.cpio", "Clamav.Test.File-6", 0},
	{"testdata", "clam.ole.doc", "Clamav.Test.File-6", 0},
	{"testdata", "clam.pdf", "Clamav.Test.File-6", 0},
	{"testdata", "clam.ppt", "Clamav.Test.File-6", 0},
	{"testdata", "clam.sis", "Clamav.Test.File-6", 0},
	{"testdata", "clam.tar.gz", "Clamav.Test.File-6", 0},
	{"testdata", "clam.tnef", "Clamav.Test.File-6", 0},
	{"testdata", "clam.zip", "Clamav.Test.File-6", 0},
	{"testdata", "clam_IScab_ext.exe", "Clamav.Test.File-6", 5092},
	{"testdata", "clam_IScab_int.exe", "Clamav.Test.File-6", 4540},
	{"testdata", "clam_ISmsi_ext.exe", "Clamav.Test.File-6", 1192},
	{"testdata", "clam_ISmsi_int.exe", "Clamav.Test.File-6", 1196},
	{"testdata", "clam_cache_emax.tgz", "Clamav.Test.File-6", 56},
	{"testdata", "clamjol.iso", "Clamav.Test.File-6", 364},
}

func testInitAll() (*Engine, error) {
	err := Init(InitDefault)
	if err != nil {
		return nil, err
	}
	eng := New()
	_, err = eng.Load(DBDir(), DbStdopt)
	if err != nil {
		return nil, errors.New("can not open virus database. please use ClamAV's freshclam tool to download a public database")
	}
	eng.Compile()
	return eng, nil
}

func TestScan(t *testing.T) {
	eng, err := testInitAll()
	if err != nil {
		t.Fatalf("testInitAll: %v", err)
	}
	defer eng.Free()

	found := false
	for _, v := range scanFiles {
		virus, scan, err := eng.ScanFile(v.dir+"/"+v.file, stdopts)
		if err != nil {
			if virus != "" {
				if virus != v.name {
					t.Errorf("ScanFile: %s/%s virus = %s (want %s); scanned: %d %v", v.dir, v.file, virus, v.name, scan, err)
				}
				found = true
			}
		}
	}
	if !found {
		fmt.Println("No virus files found. Please copy the files from ClamAV's test/ directory into testdata/")
	}
}

func benchmarkScanFile(b *testing.B, path string) {
	b.StopTimer()
	eng, err := testInitAll()
	if err != nil {
		b.Fatalf("testInitAll: %v", err)
	}
	defer eng.Free()
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		virus, scan, err := eng.ScanFile(path, stdopts)
		b.SetBytes(int64(scan * CountPrecision))
		if virus == "" {
			b.Fatalf("not a virus: %v", err)
		} else if virus != "" {
			continue
		} else if err != nil {
			b.Fatalf("%v", err)
		}
	}
}

// Benchmark a tiny (.5K bytes) virus file
func BenchmarkScanTiny1(b *testing.B) { benchmarkScanFile(b, "testdata/clam.exe") }
func BenchmarkScanTiny2(b *testing.B) { benchmarkScanFile(b, "testdata/clam.tar.gz") }
func BenchmarkScanTiny3(b *testing.B) { benchmarkScanFile(b, "testdata/clam.bz2.zip") }
func BenchmarkScanTiny4(b *testing.B) { benchmarkScanFile(b, "testdata/clam-v2.rar") }

// Benchmark a small (<=50K) virus file
func BenchmarkScanSmall1(b *testing.B) { benchmarkScanFile(b, "testdata/clam-nsis.exe") }
func BenchmarkScanSmall2(b *testing.B) { benchmarkScanFile(b, "testdata/clam.ppt") }
func BenchmarkScanSmall3(b *testing.B) { benchmarkScanFile(b, "testdata/clam.exe.rtf") }

// Benchmark a medium-sized (370K) virus file
func BenchmarkScanMedium1(b *testing.B) { benchmarkScanFile(b, "testdata/clamjol.iso") }
func BenchmarkScanMedium2(b *testing.B) { benchmarkScanFile(b, "testdata/clam.iso") }
func BenchmarkScanMedium3(b *testing.B) { benchmarkScanFile(b, "testdata/clam.ea06.exe") }

// Benchmark a large (<=1.7MB) virus file
func BenchmarkScanLarge1(b *testing.B) { benchmarkScanFile(b, "testdata/clam_IScab_ext.exe") }
func BenchmarkScanLarge2(b *testing.B) { benchmarkScanFile(b, "testdata/clam_IScab_int.exe") }
func BenchmarkScanLarge3(b *testing.B) { benchmarkScanFile(b, "testdata/clam_ISmsi_ext.exe") }
