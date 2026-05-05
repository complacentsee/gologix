package gologix

import (
	"context"
	"net"
	"testing"
	"time"
)

// nopConn discards all writes and reports a synthetic remote address. Used
// in tests where we don't care about the wire bytes the server tries to
// emit, only that dispatch progresses without panicking.
type nopConn struct{}

func (nopConn) Read(b []byte) (int, error)         { return 0, nil }
func (nopConn) Write(b []byte) (int, error)        { return len(b), nil }
func (nopConn) Close() error                       { return nil }
func (nopConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (nopConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (nopConn) SetDeadline(time.Time) error        { return nil }
func (nopConn) SetReadDeadline(time.Time) error    { return nil }
func (nopConn) SetWriteDeadline(time.Time) error   { return nil }

// TestExplicitHandlerFunc_SatisfiesInterface ensures the function adapter
// works as an ExplicitHandler. Pure compile-time + a trivial call.
func TestExplicitHandlerFunc_SatisfiesInterface(t *testing.T) {
	called := false
	var h ExplicitHandler = ExplicitHandlerFunc(func(_ context.Context, req ExplicitRequest) ExplicitResponse {
		called = true
		if req.Service != CIPService_SetAttributeSingle {
			t.Errorf("got service 0x%02x, want 0x%02x", byte(req.Service), byte(CIPService_SetAttributeSingle))
		}
		return ExplicitResponse{Status: CIPStatus_OK}
	})
	resp := h.ServeCIP(context.Background(), ExplicitRequest{Service: CIPService_SetAttributeSingle})
	if !called {
		t.Fatal("handler was not invoked")
	}
	if resp.Status != CIPStatus_OK {
		t.Errorf("got status 0x%02x, want 0x00", byte(resp.Status))
	}
}

// TestDispatchExplicit_NilMuxReturnsServiceNotSupported verifies that
// dispatchExplicit short-circuits when ExplicitMux is nil and returns
// 0x08 Service Not Supported without panicking. This is the
// backward-compatibility guarantee — existing consumers see this branch
// only via the modified default switch arms, where it is the right
// response code anyway.
func TestDispatchExplicit_NilMuxReturnsServiceNotSupported(t *testing.T) {
	srv := NewServer(NewRouter())
	if srv.ExplicitMux != nil {
		t.Fatal("default ExplicitMux must be nil for backward compatibility")
	}
	h := &serverTCPHandler{server: srv}
	item := newItem(cipItem_ConnectedData, nil)
	resp, err := h.dispatchExplicit(CIPService_SetAttributeSingle, 3, true, &item)
	if err != nil {
		t.Errorf("err=%v, want nil", err)
	}
	if resp.Status != CIPStatus_ServiceNotSupported {
		t.Errorf("status=0x%02x, want 0x%02x (ServiceNotSupported)",
			byte(resp.Status), byte(CIPStatus_ServiceNotSupported))
	}
}

// TestDispatchExplicit_ParsesPathAndData feeds dispatchExplicit a synthetic
// item containing a Class 0x04 / Instance 1024 / Attribute 3 EPATH followed
// by a 4-byte data payload, and asserts the handler receives the parsed
// values and the trailing bytes.
func TestDispatchExplicit_ParsesPathAndData(t *testing.T) {
	var got ExplicitRequest
	srv := NewServer(NewRouter())
	srv.ExplicitMux = ExplicitHandlerFunc(func(_ context.Context, req ExplicitRequest) ExplicitResponse {
		got = req
		return ExplicitResponse{Status: CIPStatus_OK}
	})
	h := &serverTCPHandler{server: srv}

	// Build a CIPItem whose Data is the EPATH (3 words = 6 bytes) followed
	// by 4 bytes of payload. EPATH segments use the 8-bit forms:
	//   0x20 0x04   class = 0x04
	//   0x24 0x00   instance = 1024 -> use 16-bit form 0x25 0x00 0x00 0x04 (4 bytes)
	// To keep the path size at 3 words exactly with class+instance+attribute
	// all 8-bit, use class=0x04, instance=0x01, attribute=0x03.
	path := []byte{
		0x20, 0x04, // class 0x04 (8-bit)
		0x24, 0x01, // instance 1 (8-bit)
		0x30, 0x03, // attribute 3 (8-bit)
	}
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	itemData := append(append([]byte{}, path...), payload...)
	item := CIPItem{Header: cipItemHeader{ID: cipItem_ConnectedData}, Data: itemData, Pos: 0}

	resp, err := h.dispatchExplicit(CIPService_SetAttributeSingle, 3, true, &item)
	if err != nil {
		t.Fatalf("dispatchExplicit: %v", err)
	}
	if resp.Status != CIPStatus_OK {
		t.Errorf("status=0x%02x, want 0x00", byte(resp.Status))
	}
	if got.Service != CIPService_SetAttributeSingle {
		t.Errorf("Service=0x%02x, want 0x10", byte(got.Service))
	}
	if got.Class != 0x04 {
		t.Errorf("Class=0x%04x, want 0x04", uint16(got.Class))
	}
	if got.Instance != 1 {
		t.Errorf("Instance=%d, want 1", uint32(got.Instance))
	}
	if got.Attribute != 3 {
		t.Errorf("Attribute=%d, want 3", uint16(got.Attribute))
	}
	if len(got.Data) != 4 || got.Data[0] != 0xDE || got.Data[3] != 0xEF {
		t.Errorf("Data=%v, want [DE AD BE EF]", got.Data)
	}
	if !got.Connected {
		t.Errorf("Connected=false, want true")
	}
}

// TestDispatchExplicit_NoAttributeSegment exercises the path where the EPATH
// has only class + instance (no attribute) — a 2-word path.
func TestDispatchExplicit_NoAttributeSegment(t *testing.T) {
	var got ExplicitRequest
	srv := NewServer(NewRouter())
	srv.ExplicitMux = ExplicitHandlerFunc(func(_ context.Context, req ExplicitRequest) ExplicitResponse {
		got = req
		return ExplicitResponse{Status: CIPStatus_OK}
	})
	h := &serverTCPHandler{server: srv}

	path := []byte{
		0x20, 0x04, // class 0x04
		0x24, 0x05, // instance 5
	}
	itemData := append([]byte{}, path...)
	item := CIPItem{Header: cipItemHeader{ID: cipItem_UnconnectedData}, Data: itemData, Pos: 0}

	_, err := h.dispatchExplicit(CIPService_GetAttributeSingle, 2, false, &item)
	if err != nil {
		t.Fatalf("dispatchExplicit: %v", err)
	}
	if got.Class != 0x04 || got.Instance != 5 {
		t.Errorf("Class=%d Instance=%d, want 4/5", uint16(got.Class), uint32(got.Instance))
	}
	if got.Attribute != 0 {
		t.Errorf("Attribute=%d, want 0 (not present)", uint16(got.Attribute))
	}
	if len(got.Data) != 0 {
		t.Errorf("Data=%v, want empty", got.Data)
	}
	if got.Connected {
		t.Errorf("Connected=true, want false")
	}
}

// TestConnectedExplicitMux_ConsumesPrelude verifies that the connected
// dispatch entry point reads exactly one path_size byte (and not also a
// phantom cmd-type byte) before handing off to dispatchExplicit. Caught a
// real off-by-one bug between the dispatch helpers — keep this test.
func TestConnectedExplicitMux_ConsumesPrelude(t *testing.T) {
	var got ExplicitRequest
	srv := NewServer(NewRouter())
	srv.ExplicitMux = ExplicitHandlerFunc(func(_ context.Context, req ExplicitRequest) ExplicitResponse {
		got = req
		return ExplicitResponse{Status: CIPStatus_OK}
	})

	// Build a synthetic connected-data item exactly matching the on-wire shape
	// post-readItems: seq, service, path_size, EPATH, data. seq + service are
	// consumed by sendUnitData before the mux fires; we set Pos to mimic that.
	const pathSizeByte = 4 // 4 words = 8 bytes (class + 16-bit instance + attr)
	itemData := []byte{
		0x01, 0x00, // seq
		byte(CIPService_SetAttributeSingle), // service
		pathSizeByte,                        // path_size
		0x20, 0x04, // class 0x04
		0x25, 0x00, 0x00, 0x04, // instance 1024 (16-bit form)
		0x30, 0x03, // attribute 3
		0xCA, 0xFE, // payload
	}
	items := []CIPItem{
		{Header: cipItemHeader{ID: cipItem_ConnectionAddress}, Data: []byte{0, 0, 0, 0}, Pos: 0},
		{Header: cipItemHeader{ID: cipItem_ConnectedData}, Data: itemData, Pos: 3},
	}

	// Mock the conn so sendExplicitConnectedReply has somewhere to write.
	h := &serverTCPHandler{server: srv, conn: &nopConn{}}
	if err := h.connectedExplicitMux(CIPService_SetAttributeSingle, items); err != nil {
		t.Fatalf("connectedExplicitMux: %v", err)
	}

	if got.Class != 0x04 {
		t.Errorf("Class=0x%04x, want 0x04", uint16(got.Class))
	}
	if got.Instance != 1024 {
		t.Errorf("Instance=%d, want 1024", uint32(got.Instance))
	}
	if got.Attribute != 3 {
		t.Errorf("Attribute=%d, want 3", uint16(got.Attribute))
	}
	if len(got.Data) != 2 || got.Data[0] != 0xCA || got.Data[1] != 0xFE {
		t.Errorf("Data=%v, want [CA FE]", got.Data)
	}
}

// TestUnconnectedExplicitMux_ConsumesPrelude exercises the unconnected
// dispatch entry point, which expects path_size as uint16 (path-size byte +
// pad byte) — a gologix convention preserved across this patch.
func TestUnconnectedExplicitMux_ConsumesPrelude(t *testing.T) {
	var got ExplicitRequest
	srv := NewServer(NewRouter())
	srv.ExplicitMux = ExplicitHandlerFunc(func(_ context.Context, req ExplicitRequest) ExplicitResponse {
		got = req
		return ExplicitResponse{Status: CIPStatus_OK}
	})

	itemData := []byte{
		0x03, 0x00, // path_size as uint16 (3 words = 6 bytes, gologix convention with pad byte)
		0x20, 0x04, // class 0x04
		0x24, 0x01, // instance 1
		0x30, 0x03, // attribute 3
		0xBE, 0xEF, // payload
	}
	item := CIPItem{Header: cipItemHeader{ID: cipItem_UnconnectedData}, Data: itemData, Pos: 0}

	h := &serverTCPHandler{server: srv, conn: &nopConn{}}
	if err := h.unconnectedExplicitMux(CIPService_SetAttributeSingle, &item); err != nil {
		t.Fatalf("unconnectedExplicitMux: %v", err)
	}

	if got.Class != 0x04 || got.Instance != 1 || got.Attribute != 3 {
		t.Errorf("got Class=%d Inst=%d Attr=%d, want 4/1/3",
			uint16(got.Class), uint32(got.Instance), uint16(got.Attribute))
	}
	if len(got.Data) != 2 || got.Data[1] != 0xEF {
		t.Errorf("Data=%v, want [BE EF]", got.Data)
	}
	if got.Connected {
		t.Errorf("Connected=true, want false")
	}
}

// TestDispatchExplicit_PathExceedsItem exercises the malformed-input path
// where the declared path size is larger than the available bytes.
func TestDispatchExplicit_PathExceedsItem(t *testing.T) {
	srv := NewServer(NewRouter())
	srv.ExplicitMux = ExplicitHandlerFunc(func(_ context.Context, _ ExplicitRequest) ExplicitResponse {
		return ExplicitResponse{Status: CIPStatus_OK}
	})
	h := &serverTCPHandler{server: srv}

	// Only 2 bytes but we'll claim path size = 3 words = 6 bytes.
	item := CIPItem{Data: []byte{0x20, 0x04}, Pos: 0}
	resp, err := h.dispatchExplicit(CIPService_SetAttributeSingle, 3, false, &item)
	if err == nil {
		t.Fatal("expected error on undersized item, got nil")
	}
	if resp.Status != CIPStatus_PathSegmentError {
		t.Errorf("status=0x%02x, want 0x04 (PathSegmentError)", byte(resp.Status))
	}
}
