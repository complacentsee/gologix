package gologix

import (
	"context"
	"fmt"
)

// ExplicitRequest is a parsed CIP explicit-message request, transport-agnostic
// (works whether the message arrived connected, unconnected, or wrapped in
// Unconnected_Send 0x52). It is passed to ExplicitHandler.ServeCIP when
// Server.ExplicitMux is set.
type ExplicitRequest struct {
	// Service is the CIP service code (e.g. 0x10 Set_Attribute_Single).
	Service CIPService

	// Class, Instance, Attribute are the EPATH segments parsed from the
	// request. Attribute is zero if the request EPATH had only class +
	// instance segments.
	Class     CIPClass
	Instance  CIPInstance
	Attribute CIPAttribute

	// Data carries the bytes that follow the EPATH — for Set_Attribute_Single
	// this is the attribute value being written; for some triggers it is
	// empty. It is the raw service payload, exactly as received.
	Data []byte

	// Connected is true if the request arrived on a connected session
	// (post-ForwardOpen). Useful for diagnostics; not part of routing.
	Connected bool
}

// ExplicitResponse is what an ExplicitHandler returns. The server adapter
// owns CIP framing — it serialises the response into the appropriate
// connected/unconnected reply for the originator.
type ExplicitResponse struct {
	// Status is the CIP general status byte (0 = success). See CIP Volume
	// 1 §3-5.5 ("General Status Codes") for the standard values.
	Status CIPStatus

	// ExtendedStatus carries optional uint16 words appended after the
	// general status. Most responses leave this nil.
	ExtendedStatus []uint16

	// Data is the response payload to return after the status header.
	// nil for a bare ack (the common case for Set_Attribute_Single).
	Data []byte
}

// ExplicitHandler is the interface a consumer-supplied router implements to
// receive explicit-message requests. Modeled on net/http.Handler: one method,
// request in, response out.
//
// When Server.ExplicitMux is non-nil, the server routes Set_Attribute_Single
// (and other services that fall through the existing native dispatch) to the
// handler. When ExplicitMux is nil, behaviour is unchanged from upstream —
// existing tag-read/write/Identity-Object users see no difference.
type ExplicitHandler interface {
	ServeCIP(ctx context.Context, req ExplicitRequest) ExplicitResponse
}

// ExplicitHandlerFunc adapts a plain function to ExplicitHandler. Useful for
// inline closures in tests and one-off handlers (e.g., a default Identity
// Object reply registered at boot).
type ExplicitHandlerFunc func(ctx context.Context, req ExplicitRequest) ExplicitResponse

// ServeCIP makes ExplicitHandlerFunc satisfy ExplicitHandler.
func (f ExplicitHandlerFunc) ServeCIP(ctx context.Context, req ExplicitRequest) ExplicitResponse {
	return f(ctx, req)
}

// dispatchExplicit parses a class/instance/[attribute] EPATH out of item,
// builds an ExplicitRequest with the residual bytes as Data, and asks
// h.server.ExplicitMux to handle it. The caller has already consumed any
// transport-specific framing (sequence counter, command type byte, path-size
// word) and positioned item at the start of the EPATH bytes.
//
// pathWords is the EPATH length in 16-bit words, matching the size field that
// preceded it in the wire format. We read that many bytes and parse them as
// class + instance + optional attribute. Anything left in item after the path
// is the request data.
func (h *serverTCPHandler) dispatchExplicit(
	service CIPService,
	pathWords int,
	connected bool,
	item *CIPItem,
) (ExplicitResponse, error) {
	if h.server.ExplicitMux == nil {
		return ExplicitResponse{Status: CIPStatus_ServiceNotSupported}, nil
	}

	pathStart := item.Pos
	pathEnd := pathStart + pathWords*2
	if pathEnd > len(item.Data) {
		return ExplicitResponse{Status: CIPStatus_PathSegmentError},
			fmt.Errorf("path size %d words extends past item end", pathWords)
	}

	cls, err := readClassSegment(item)
	if err != nil {
		return ExplicitResponse{Status: CIPStatus_PathSegmentError}, fmt.Errorf("read class: %w", err)
	}
	inst, err := readInstanceSegment(item)
	if err != nil {
		return ExplicitResponse{Status: CIPStatus_PathSegmentError}, fmt.Errorf("read instance: %w", err)
	}

	var attr CIPAttribute
	if item.Pos < pathEnd {
		attr, err = readAttributeSegment(item)
		if err != nil {
			return ExplicitResponse{Status: CIPStatus_PathSegmentError}, fmt.Errorf("read attribute: %w", err)
		}
	}

	// Anything between item.Pos and pathEnd is unparsed path padding (CIP
	// allows trailing padding to keep the EPATH on a 16-bit word boundary).
	// Skip it; the data follows the path.
	if item.Pos < pathEnd {
		item.Pos = pathEnd
	}

	req := ExplicitRequest{
		Service:   service,
		Class:     cls,
		Instance:  inst,
		Attribute: attr,
		Data:      append([]byte(nil), item.Rest()...),
		Connected: connected,
	}
	return h.server.ExplicitMux.ServeCIP(context.Background(), req), nil
}

// readClassSegment reads a CIP logical class segment, consuming the
// reserved/pad byte that follows the type byte for 16-bit and 32-bit forms.
// Per CIP Vol 1 §C-1.4.1.2 the wire forms are:
//
//	8-bit:  0x20, value
//	16-bit: 0x21, RESERVED, value_lo, value_hi
//	32-bit: 0x22, RESERVED, value[4]
//
// Existing CIPClass.Read does not consume the RESERVED byte, leaving callers
// off by one for any non-trivial path. We don't want to change the public
// Read method's behaviour (callers may be relying on the current byte
// accounting), so this is an additive helper used only by the explicit mux
// dispatch path.
func readClassSegment(item *CIPItem) (CIPClass, error) {
	typ, err := item.Byte()
	if err != nil {
		return 0, fmt.Errorf("class type byte: %w", err)
	}
	switch cipClassSize(typ) {
	case cipClass_8bit:
		v, err := item.Byte()
		if err != nil {
			return 0, fmt.Errorf("class 8-bit value: %w", err)
		}
		return CIPClass(v), nil
	case cipClass_16bit:
		if _, err := item.Byte(); err != nil {
			return 0, fmt.Errorf("class 16-bit pad: %w", err)
		}
		v, err := item.Uint16()
		if err != nil {
			return 0, fmt.Errorf("class 16-bit value: %w", err)
		}
		return CIPClass(v), nil
	default:
		return 0, fmt.Errorf("expected 0x20 or 0x21 but got class type 0x%02x", typ)
	}
}

// readInstanceSegment is the instance counterpart of readClassSegment. CIP
// 8-bit type is 0x24, 16-bit is 0x25, 32-bit is 0x26. We support 8/16-bit;
// 32-bit instances exist but are vanishingly rare in practice and would
// require widening CIPInstance handling we don't yet need.
func readInstanceSegment(item *CIPItem) (CIPInstance, error) {
	typ, err := item.Byte()
	if err != nil {
		return 0, fmt.Errorf("instance type byte: %w", err)
	}
	switch cipInstanceSize(typ) {
	case cipInstance_8bit:
		v, err := item.Byte()
		if err != nil {
			return 0, fmt.Errorf("instance 8-bit value: %w", err)
		}
		return CIPInstance(v), nil
	case cipInstance_16bit:
		if _, err := item.Byte(); err != nil {
			return 0, fmt.Errorf("instance 16-bit pad: %w", err)
		}
		v, err := item.Uint16()
		if err != nil {
			return 0, fmt.Errorf("instance 16-bit value: %w", err)
		}
		return CIPInstance(v), nil
	default:
		return 0, fmt.Errorf("expected 0x24 or 0x25 but got instance type 0x%02x", typ)
	}
}

// readAttributeSegment is the attribute counterpart. 8-bit type is 0x30,
// 16-bit is 0x31.
func readAttributeSegment(item *CIPItem) (CIPAttribute, error) {
	typ, err := item.Byte()
	if err != nil {
		return 0, fmt.Errorf("attribute type byte: %w", err)
	}
	switch cipAttributeType(typ) {
	case cipAttribute_8bit:
		v, err := item.Byte()
		if err != nil {
			return 0, fmt.Errorf("attribute 8-bit value: %w", err)
		}
		return CIPAttribute(v), nil
	case cipAttribute_16bit:
		if _, err := item.Byte(); err != nil {
			return 0, fmt.Errorf("attribute 16-bit pad: %w", err)
		}
		v, err := item.Uint16()
		if err != nil {
			return 0, fmt.Errorf("attribute 16-bit value: %w", err)
		}
		return CIPAttribute(v), nil
	default:
		return 0, fmt.Errorf("expected 0x30 or 0x31 but got attribute type 0x%02x", typ)
	}
}

// connectedExplicitMux is the connected-dispatch entry point invoked from
// sendUnitData when the service is Set_Attribute_Single or any other service
// that falls through to the explicit mux.
//
// Wire format (inside the cipItem_ConnectedData item):
//
//	seq         uint16
//	service     byte    <- consumed by sendUnitData before we're called
//	path_size   byte    <- in 16-bit words
//	EPATH       path_size*2 bytes
//	data        variable
//
// sendUnitData has already consumed seq and service, so items[1] is positioned
// at path_size. We read it and hand off to dispatchExplicit.
func (h *serverTCPHandler) connectedExplicitMux(service CIPService, items []CIPItem) error {
	item := &items[1]

	pathSize, err := item.Byte()
	if err != nil {
		return fmt.Errorf("read path size: %w", err)
	}

	resp, dispatchErr := h.dispatchExplicit(service, int(pathSize), true, item)
	if dispatchErr != nil {
		h.server.Logger.Warn("explicit dispatch error",
			"service", service, "err", dispatchErr)
	}
	return h.sendExplicitConnectedReply(service, resp)
}

// unconnectedExplicitMux is the unconnected-dispatch entry point invoked from
// unconnectedData when the service is Set_Attribute_Single or any other
// service that falls through to the explicit mux. The caller has already
// consumed the service byte; item is positioned at the path-size byte.
//
// Unconnected explicit messages carry: path-size byte (in 16-bit words),
// EPATH, then optional service data — per CIP Vol 1 §3-4.4.1. There is no
// pad byte between the size and the EPATH.
func (h *serverTCPHandler) unconnectedExplicitMux(service CIPService, item *CIPItem) error {
	pathSize, err := item.Byte()
	if err != nil {
		return fmt.Errorf("read path size: %w", err)
	}

	resp, dispatchErr := h.dispatchExplicit(service, int(pathSize), false, item)
	if dispatchErr != nil {
		h.server.Logger.Warn("explicit dispatch error",
			"service", service, "err", dispatchErr)
	}
	return h.sendExplicitUnconnectedReply(service, resp)
}

// sendExplicitConnectedReply writes the response for a connected explicit
// message back through the existing unit-data path. service must be the
// originating service (not yet OR'd with the response bit); the helper
// applies AsResponse().
func (h *serverTCPHandler) sendExplicitConnectedReply(service CIPService, resp ExplicitResponse) error {
	items := make([]CIPItem, 2)
	items[0] = newItem(cipItem_ConnectionAddress, h.TOConnectionID)
	items[1] = newItem(cipItem_ConnectedData, nil)
	hdr := msgWriteResultHeader{
		SequenceCount:  h.UnitDataSequencer,
		Service:        service.AsResponse(),
		Reserved:       0,
		Status:         resp.Status,
		StatusExtended: byte(len(resp.ExtendedStatus)),
	}
	if err := items[1].Serialize(hdr); err != nil {
		return fmt.Errorf("serialize explicit reply header: %w", err)
	}
	for _, w := range resp.ExtendedStatus {
		if err := items[1].Serialize(w); err != nil {
			return fmt.Errorf("serialize extended status: %w", err)
		}
	}
	if len(resp.Data) > 0 {
		if err := items[1].Serialize(resp.Data); err != nil {
			return fmt.Errorf("serialize explicit reply data: %w", err)
		}
	}
	itemData, err := serializeItems(items)
	if err != nil {
		return fmt.Errorf("serialize explicit reply items: %w", err)
	}
	return h.send(cipCommandSendUnitData, itemData)
}

// sendExplicitUnconnectedReply is the unconnected counterpart of
// sendExplicitConnectedReply. Used by the unconnected dispatch and by the
// 0x52 Unconnected_Send unwrap path.
func (h *serverTCPHandler) sendExplicitUnconnectedReply(service CIPService, resp ExplicitResponse) error {
	items := make([]CIPItem, 2)
	items[0] = newItem(cipItem_Null, nil)
	items[1] = newItem(cipItem_UnconnectedData, nil)
	hdr := msgUnconnWriteResultHeader{
		Service:        service.AsResponse(),
		Reserved:       0,
		Status:         resp.Status,
		StatusExtended: byte(len(resp.ExtendedStatus)),
	}
	if err := items[1].Serialize(hdr); err != nil {
		return fmt.Errorf("serialize explicit reply header: %w", err)
	}
	for _, w := range resp.ExtendedStatus {
		if err := items[1].Serialize(w); err != nil {
			return fmt.Errorf("serialize extended status: %w", err)
		}
	}
	if len(resp.Data) > 0 {
		if err := items[1].Serialize(resp.Data); err != nil {
			return fmt.Errorf("serialize explicit reply data: %w", err)
		}
	}
	itemData, err := serializeItems(items)
	if err != nil {
		return fmt.Errorf("serialize explicit reply items: %w", err)
	}
	return h.send(cipCommandSendRRData, itemData)
}
