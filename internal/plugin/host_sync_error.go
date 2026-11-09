package plugin

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"strconv"
	"syscall"
)

// Only fixed, credential-free diagnostics leave the synchronization boundary.
// Never forward response bodies, request URLs, YAML errors or arbitrary errors.
type hostSyncFailure struct{ code, message string }

func (e *hostSyncFailure) Error() string { return e.message }
func newHostSyncFailure(code, message string) error {
	return &hostSyncFailure{code: code, message: message}
}
func hostSyncDiagnostic(err error) (string, string) {
	var failure *hostSyncFailure
	if errors.As(err, &failure) {
		return failure.code, failure.message
	}
	return "sync_failed", "CPA 同步失败，请检查宿主服务并刷新重试"
}

func hostSyncTransportFailure(err error) error {
	if errors.Is(err, context.DeadlineExceeded) {
		return newHostSyncFailure("timeout", "连接宿主管理接口超时，请检查监听地址与端口")
	}
	if errors.Is(err, context.Canceled) {
		return newHostSyncFailure("cancelled", "宿主同步请求已取消，可刷新重试")
	}
	var verify *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &verify) || errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return newHostSyncFailure("tls_verify", "宿主 TLS 证书验证失败，请检查 server.tls 的证书及名称")
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return newHostSyncFailure("dns", "宿主监听地址无法解析，请检查 server.host")
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return newHostSyncFailure("connection_refused", "宿主管理接口拒绝连接，请检查 server.host、server.port 和监听状态")
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return newHostSyncFailure("timeout", "连接宿主管理接口超时，请检查监听地址与端口")
	}
	return newHostSyncFailure("connection_failed", "无法连接宿主管理接口，请检查监听地址、端口和 TLS 配置")
}

func hostSyncHTTPFailure(method string, status int) error {
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return newHostSyncFailure("authorization", "宿主管理接口返回 "+strconv.Itoa(status)+" "+http.StatusText(status)+"，请重新验证 Management Key 并检查本机管理访问策略")
	case http.StatusNotFound:
		return newHostSyncFailure("endpoint_missing", "宿主找不到 API Key 管理接口（HTTP 404），请检查宿主版本及监听端口")
	case http.StatusMethodNotAllowed:
		return newHostSyncFailure("method_unsupported", "宿主不支持 "+method+" 密钥同步（HTTP 405），请检查宿主版本")
	default:
		return newHostSyncFailure("http_status", "宿主管理接口请求失败："+method+" HTTP "+strconv.Itoa(status)+" "+http.StatusText(status))
	}
}
