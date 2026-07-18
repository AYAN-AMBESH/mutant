// Package serve implements the per-connection VM spawn behind the net_serve
// builtin (dev-sec-platform-upgrades). It lives in its own package because it
// imports compiler/vm, which the builtin package cannot (import cycle). It wires
// itself into builtin via the NetServe*Hook variables at init time; main.go must
// import this package (blank import is fine) so init() runs.
//
// Model: a handler .mut is compiled ONCE to bytecode (parse -> compile ->
// EncryptByteCode, mirroring the REPL's in-process path), cached by path, then
// executed on a fresh VM per connection. Each VM gets its own stack/frames and
// its own globals slice, and shares the read-only, already-encrypted bytecode of
// the cached handler. The connection handle and shared arg are injected as two
// predefined globals (serve_conn, serve_arg). Per-connection cleanup uses
// CleanupRuntimeSensitiveData(clearGlobals=true, clearConstants=false) so a
// finishing worker never wipes the bytecode its siblings are still running.
package serve

import (
	"fmt"
	"os"
	"sync"

	"mutant/builtin"
	"mutant/compiler"
	"mutant/global"
	"mutant/lexer"
	"mutant/mutil"
	"mutant/object"
	"mutant/parser"
	"mutant/vm"
)

// servePassword keys the in-memory EncryptByteCode/VM XOR. It never touches disk;
// any consistent value works, exactly as replPassword does for the REPL.
const servePassword = "mutant-net-serve-inproc-v1"

type prepared struct {
	bc      *compiler.ByteCode
	connIdx int
	argIdx  int
	arg     object.Object
}

var (
	cacheMu sync.Mutex
	cache   = map[string]*prepared{}
)

func init() { Install() }

// Install wires the spawn implementation into the builtin package.
func Install() {
	builtin.NetServePrepareHook = prepare
	builtin.NetServeRunHook = run
}

// prepare compiles and caches a handler once. Subsequent calls for the same path
// are no-ops (the first arg wins).
func prepare(handlerPath string, arg object.Object) *object.Error {
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if _, ok := cache[handlerPath]; ok {
		return nil
	}

	src, err := os.ReadFile(handlerPath)
	if err != nil {
		return errObj("net_serve: cannot read handler %q: %s", handlerPath, err.Error())
	}

	p := parser.New(lexer.New(string(src)))
	program := p.ParseProgram()
	if perrs := p.Errors(); len(perrs) > 0 {
		return errObj("net_serve: handler %q parse error: %s", handlerPath, perrs[0])
	}

	// Fresh symbol table with all builtins defined (BuiltinScope, no global slot),
	// then two predefined GLOBAL symbols the handler reads. Defining these first
	// pins them to global indexes 0 and 1; the handler's own lets take 2+.
	st := compiler.NewSymbolTable()
	for i, b := range builtin.Builtins {
		st.DefineBuiltin(i, b.Name)
	}
	connSym := st.Define("serve_conn")
	argSym := st.Define("serve_arg")

	comp := compiler.NewWithState(st, []object.Object{})
	if cerr := comp.Compile(program); cerr != nil {
		return errObj("net_serve: handler %q compile error: %s", handlerPath, cerr.Error())
	}

	bc := mutil.EncryptByteCode(comp.ByteCode(), servePassword)
	cache[handlerPath] = &prepared{bc: bc, connIdx: connSym.Index, argIdx: argSym.Index, arg: arg}
	return nil
}

// run executes the prepared handler for one connection on a fresh VM.
func run(handlerPath string, connHandle int64) {
	cacheMu.Lock()
	pr := cache[handlerPath]
	cacheMu.Unlock()
	if pr == nil {
		return
	}

	globals := make([]object.Object, global.GlobalSize)
	globals[pr.connIdx] = &object.Integer{Value: connHandle}
	if pr.arg != nil {
		globals[pr.argIdx] = pr.arg
	} else {
		globals[pr.argIdx] = &object.Null{}
	}

	machine := vm.NewWithGlobalStoreAndPassword(pr.bc, globals, servePassword)
	// NOTE: do NOT call CleanupRuntimeSensitiveData here. Its stack sweep calls
	// clearObjectSensitiveData on stack entries, which alias the SHARED constant
	// objects of pr.bc — a finishing worker would zero the encrypted constants
	// its concurrent siblings are still decrypting (SecureXOR then fails on the
	// emptied buffer -> "unusable as a hashkey: ENCRYPTED"). Reads of the shared
	// bytecode (SecureXOROneAt on instructions, DecryptObject on constants) are
	// pure/read-only, so leaving cleanup off makes concurrent execution safe; the
	// per-connection stack/globals are GC-reclaimed when the goroutine returns.
	if err := machine.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "[net_serve] handler error (conn %d): %s\n", connHandle, err.Error())
	}
}

func errObj(format string, a ...any) *object.Error {
	return &object.Error{Message: fmt.Sprintf(format, a...)}
}
