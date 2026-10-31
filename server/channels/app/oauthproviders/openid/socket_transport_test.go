package oauthopenid

import (
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSocketTransport(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "auth.socket")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)

	received := make(chan *http.Request, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	client := &http.Client{Transport: NewSocketTransport(socket)}
	resp, err := client.Get("https://auth.example.com/api/oidc/userinfo")
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, "ok", string(body))

	r := <-received
	assert.Equal(t, "auth.example.com", r.Host)
	assert.Equal(t, "/api/oidc/userinfo", r.URL.Path)
	assert.Equal(t, "https", r.Header.Get("X-Forwarded-Proto"))
	assert.Equal(t, "auth.example.com", r.Header.Get("X-Forwarded-Host"))
}
