package oauthopenid

import (
	"context"
	"net"
	"net/http"
)

type SocketTransport struct {
	transport *http.Transport
}

func NewSocketTransport(socket string) *SocketTransport {
	return &SocketTransport{
		transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dialer net.Dialer
				return dialer.DialContext(ctx, "unix", socket)
			},
		},
	}
}

func (t *SocketTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	viaSocket := r.Clone(r.Context())
	viaSocket.URL.Scheme = "http"
	viaSocket.Header.Set("X-Forwarded-Proto", "https")
	viaSocket.Header.Set("X-Forwarded-Host", r.URL.Host)
	return t.transport.RoundTrip(viaSocket)
}
