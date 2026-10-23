package main

/*
#include <stdint.h>
#include <stdlib.h>

typedef struct {
	void* ptr;
	size_t len;
} cliproxy_buffer;

typedef int (*cliproxy_host_call_fn)(void*, const char*, const uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_host_free_fn)(void*, size_t);

typedef struct {
	uint32_t abi_version;
	void* host_ctx;
	cliproxy_host_call_fn call;
	cliproxy_host_free_fn free_buffer;
} cliproxy_host_api;

typedef int (*cliproxy_plugin_call_fn)(char*, uint8_t*, size_t, cliproxy_buffer*);
typedef void (*cliproxy_plugin_free_fn)(void*, size_t);
typedef void (*cliproxy_plugin_shutdown_fn)(void);

typedef struct {
	uint32_t abi_version;
	cliproxy_plugin_call_fn call;
	cliproxy_plugin_free_fn free_buffer;
	cliproxy_plugin_shutdown_fn shutdown;
} cliproxy_plugin_api;

extern int cliproxyPluginCall(char*, uint8_t*, size_t, cliproxy_buffer*);
extern void cliproxyPluginFree(void*, size_t);
extern void cliproxyPluginShutdown(void);

static const cliproxy_host_api* stored_host;

static void store_host_api(const cliproxy_host_api* host) {
	stored_host = host;
}

static int call_host_api(const char* method, const uint8_t* request, size_t request_len, cliproxy_buffer* response) {
	if (stored_host == NULL || stored_host->call == NULL) {
		return 1;
	}
	return stored_host->call(stored_host->host_ctx, method, request, request_len, response);
}

static void free_host_buffer(void* ptr, size_t len) {
	if (stored_host != NULL && stored_host->free_buffer != NULL && ptr != NULL) {
		stored_host->free_buffer(ptr, len);
	}
}
*/
import "C"

import (
	"fmt"
	"unsafe"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/YzMzx/cpa-plugin-key/internal/plugin"
)

var globalManager = plugin.NewManager(invokeHostABI)

func main() {}

//export cliproxy_plugin_init
func cliproxy_plugin_init(host *C.cliproxy_host_api, pluginOut *C.cliproxy_plugin_api) C.int {
	if pluginOut == nil {
		return 1
	}
	if host != nil && uint32(host.abi_version) != pluginabi.ABIVersion {
		return 1
	}
	C.store_host_api(host)
	pluginOut.abi_version = C.uint32_t(pluginabi.ABIVersion)
	pluginOut.call = C.cliproxy_plugin_call_fn(C.cliproxyPluginCall)
	pluginOut.free_buffer = C.cliproxy_plugin_free_fn(C.cliproxyPluginFree)
	pluginOut.shutdown = C.cliproxy_plugin_shutdown_fn(C.cliproxyPluginShutdown)
	return 0
}

//export cliproxyPluginCall
func cliproxyPluginCall(method *C.char, request *C.uint8_t, requestLen C.size_t, response *C.cliproxy_buffer) C.int {
	if response != nil {
		response.ptr = nil
		response.len = 0
	}
	if method == nil {
		writeResponseBuffer(response, plugin.ErrorEnvelope("invalid_method", "method is required"))
		return 1
	}

	var reqBytes []byte
	if request != nil && requestLen > 0 {
		reqBytes = C.GoBytes(unsafe.Pointer(request), C.int(requestLen))
	}

	raw, err := globalManager.HandleRPC(C.GoString(method), reqBytes)
	if err != nil {
		writeResponseBuffer(response, plugin.ErrorEnvelope("plugin_error", err.Error()))
		return 1
	}
	writeResponseBuffer(response, raw)
	return 0
}

//export cliproxyPluginFree
func cliproxyPluginFree(ptr unsafe.Pointer, length C.size_t) {
	if ptr != nil {
		C.free(ptr)
	}
	_ = length
}

//export cliproxyPluginShutdown
func cliproxyPluginShutdown() {
	globalManager.Shutdown()
}

func writeResponseBuffer(response *C.cliproxy_buffer, raw []byte) {
	if response == nil || len(raw) == 0 {
		return
	}
	ptr := C.CBytes(raw)
	if ptr == nil {
		return
	}
	response.ptr = ptr
	response.len = C.size_t(len(raw))
}

func invokeHostABI(method string, payload []byte) ([]byte, error) {
	cMethod := C.CString(method)
	defer C.free(unsafe.Pointer(cMethod))

	var reqPtr *C.uint8_t
	if len(payload) > 0 {
		cPayload := C.CBytes(payload)
		defer C.free(cPayload)
		reqPtr = (*C.uint8_t)(cPayload)
	}

	var respBuf C.cliproxy_buffer
	rc := C.call_host_api(cMethod, reqPtr, C.size_t(len(payload)), &respBuf)
	if respBuf.ptr != nil {
		defer C.free_host_buffer(respBuf.ptr, respBuf.len)
	}
	if rc != 0 {
		return nil, fmt.Errorf("host callback %s returned code %d", method, int(rc))
	}
	if respBuf.ptr == nil || respBuf.len == 0 {
		return nil, nil
	}
	return C.GoBytes(respBuf.ptr, C.int(respBuf.len)), nil
}
