package server

import (
	"encoding/binary"
	"image"
	"io"
	"net"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCapturer returns a 100x100 image for test sessions.
type testCapturer struct{}

func (t *testCapturer) Width() int                      { return 100 }
func (t *testCapturer) Height() int                     { return 100 }
func (t *testCapturer) Capture() (*image.RGBA, error)   { return image.NewRGBA(image.Rect(0, 0, 100, 100)), nil }

func startTestServer(t *testing.T, disableAuth bool, jwtConfig *JWTConfig) (net.Addr, *Server) {
	t.Helper()

	srv := New(&testCapturer{}, &StubInputInjector{}, "")
	srv.SetDisableAuth(disableAuth)
	if jwtConfig != nil {
		srv.SetJWTConfig(jwtConfig)
	}

	addr := netip.MustParseAddrPort("127.0.0.1:0")
	network := netip.MustParsePrefix("127.0.0.0/8")
	require.NoError(t, srv.Start(t.Context(), addr, network))
	// Override local address so source validation doesn't reject 127.0.0.1 as "own IP".
	srv.localAddr = netip.MustParseAddr("10.99.99.1")
	t.Cleanup(func() { _ = srv.Stop() })

	return srv.listener.Addr(), srv
}

func TestAuthEnabled_NoJWTConfig_RejectsConnection(t *testing.T) {
	addr, _ := startTestServer(t, false, nil)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Send session header: attach mode, no username, no JWT.
	header := []byte{ModeAttach, 0, 0, 0, 0}
	_, err = conn.Write(header)
	require.NoError(t, err)

	// Server should send RFB version then security failure.
	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err)
	assert.Equal(t, "RFB 003.008\n", string(version[:]))

	// Write client version to proceed through handshake.
	_, err = conn.Write(version[:])
	require.NoError(t, err)

	// Read security types: 0 means failure, followed by reason.
	var numTypes [1]byte
	_, err = io.ReadFull(conn, numTypes[:])
	require.NoError(t, err)
	assert.Equal(t, byte(0), numTypes[0], "should have 0 security types (failure)")

	var reasonLen [4]byte
	_, err = io.ReadFull(conn, reasonLen[:])
	require.NoError(t, err)

	reason := make([]byte, binary.BigEndian.Uint32(reasonLen[:]))
	_, err = io.ReadFull(conn, reason)
	require.NoError(t, err)
	assert.Contains(t, string(reason), "identity provider", "rejection reason should mention missing IdP config")
}

func TestAuthDisabled_AllowsConnection(t *testing.T) {
	addr, _ := startTestServer(t, true, nil)

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Send session header: attach mode, no username, no JWT.
	header := []byte{ModeAttach, 0, 0, 0, 0}
	_, err = conn.Write(header)
	require.NoError(t, err)

	// Server should send RFB version.
	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err)
	assert.Equal(t, "RFB 003.008\n", string(version[:]))

	// Write client version.
	_, err = conn.Write(version[:])
	require.NoError(t, err)

	// Should get security types (not 0 = failure).
	var numTypes [1]byte
	_, err = io.ReadFull(conn, numTypes[:])
	require.NoError(t, err)
	assert.NotEqual(t, byte(0), numTypes[0], "should have at least one security type (auth disabled)")
}

func TestAuthEnabled_EmptyJWT_Rejected(t *testing.T) {
	// Auth enabled with a (bogus) JWT config: connections without JWT should be rejected.
	addr, _ := startTestServer(t, false, &JWTConfig{
		Issuer:       "https://example.com",
		KeysLocation: "https://example.com/.well-known/jwks.json",
		Audiences:    []string{"test"},
	})

	conn, err := net.Dial("tcp", addr.String())
	require.NoError(t, err)
	defer conn.Close()

	// Send session header with empty JWT.
	header := []byte{ModeAttach, 0, 0, 0, 0}
	_, err = conn.Write(header)
	require.NoError(t, err)

	var version [12]byte
	_, err = io.ReadFull(conn, version[:])
	require.NoError(t, err)

	_, err = conn.Write(version[:])
	require.NoError(t, err)

	var numTypes [1]byte
	_, err = io.ReadFull(conn, numTypes[:])
	require.NoError(t, err)
	assert.Equal(t, byte(0), numTypes[0], "should reject with 0 security types")
}
