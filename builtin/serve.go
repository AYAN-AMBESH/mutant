package builtin

// net_serve — concurrent per-connection dispatch (dev-sec-platform-upgrades).
//
// Mutant's proxy examples are serial: a single VM runs a `for { net_accept ... }`
// loop and handles one connection to completion before accepting the next,
// because a blocking net_accept executes inside the one VM `Run()` loop. net_serve
// breaks that: it runs the accept loop in Go and spawns a FRESH per-connection VM
// (running a handler .mut compiled once) for every accepted connection, so many
// connections are serviced in parallel.
//
// The actual VM spawn lives in the `serve` package (which imports compiler/vm);
// builtin cannot import those without an import cycle, so the spawn is injected
// here as a pair of hooks that `serve.init()` installs at startup.

import "mutant/object"

// NetServePrepareHook compiles+caches a handler .mut once and records the value
// that will be passed to every invocation as `serve_arg`. Returns an error object
// on parse/compile failure. Installed by the `serve` package.
var NetServePrepareHook func(handlerPath string, arg object.Object) *object.Error

// NetServeRunHook runs the prepared handler for one accepted connection, with the
// connection handle exposed to the handler as the predefined global `serve_conn`.
// Installed by the `serve` package. Intended to be called on its own goroutine.
var NetServeRunHook func(handlerPath string, connHandle int64)

// NetServe accepts connections on a listener and dispatches each to a fresh VM
// running `handler_path`. It blocks (like an accept loop) and only returns on a
// listener error.
//
// net_serve(listener_handle INTEGER, handler_path STRING, arg?) -> (never, err)
//
// The handler .mut reads its connection via the predefined global `serve_conn`
// (an INTEGER handle usable with net_conn_* / http_conn_* / net_tls_upgrade_*),
// and the optional shared `arg` via `serve_arg`. `arg` is shared by reference
// across all handler goroutines, so pass an immutable value (STRING/INTEGER,
// e.g. a JSON-encoded context) — not a hash you intend to mutate.
func NetServe(args ...object.Object) object.Object {
	if len(args) != 2 && len(args) != 3 {
		return resultAndError(nil, newError("wrong number of arguments. got=%d, want=2 or 3", len(args)))
	}
	handleObj, ok := args[0].(*object.Integer)
	if !ok {
		return resultAndError(nil, newError("argument 1 to `net_serve` must be INTEGER, got %s", args[0].Type()))
	}
	pathObj, ok := args[1].(*object.String)
	if !ok {
		return resultAndError(nil, newError("argument 2 to `net_serve` must be STRING, got %s", args[1].Type()))
	}
	var arg object.Object = &object.Null{}
	if len(args) == 3 {
		arg = args[2]
	}

	if NetServePrepareHook == nil || NetServeRunHook == nil {
		return resultAndError(nil, newError("net_serve: concurrency runtime not installed"))
	}

	ml, ok := lookupListener(handleObj.Value)
	if !ok {
		return resultAndError(nil, newError("net_serve: unknown listener handle %d", handleObj.Value))
	}

	if errObj := NetServePrepareHook(pathObj.Value, arg); errObj != nil {
		return resultAndError(nil, errObj)
	}

	for {
		conn, err := ml.ln.Accept()
		if err != nil {
			return resultAndError(nil, newError("net_serve: accept failed: %s", err.Error()))
		}
		id := registerConn(conn, ml.isTLS)
		go NetServeRunHook(pathObj.Value, id)
	}
}
