package wire

// Internal Indications (IIN): the two octets an outstation returns in
// every response (application FC 129 Response / 130 Unsolicited
// Response), right after the function code. IEEE 1815 §4.4.
//
// The IIN is a free intrusion signal that rides in the reply and is
// almost never read: Device Restart / Device Trouble / Configuration
// Corrupt confirm that something changed the device's state, and a
// burst of Function-not-supported / Object-unknown / Parameter-error
// is somebody enumerating or fuzzing the outstation.

// IIN1 (first octet) bits.
const (
	IIN1Broadcast     uint8 = 0x01 // a broadcast message was received
	IIN1Class1Events  uint8 = 0x02 // Class 1 data available
	IIN1Class2Events  uint8 = 0x04 // Class 2 data available
	IIN1Class3Events  uint8 = 0x08 // Class 3 data available
	IIN1NeedTime      uint8 = 0x10 // time synchronisation required
	IIN1LocalControl  uint8 = 0x20 // a point is in local (not remote) control
	IIN1DeviceTrouble uint8 = 0x40 // device-specific trouble
	IIN1DeviceRestart uint8 = 0x80 // the outstation restarted
)

// IIN2 (second octet) bits.
const (
	IIN2FuncNotSupp         uint8 = 0x01 // function code not supported
	IIN2ObjectUnknown       uint8 = 0x02 // requested object(s) unknown
	IIN2ParameterError      uint8 = 0x04 // parameter out of range / bad qualifier
	IIN2EventBufferOverflow uint8 = 0x08 // events were lost
	IIN2AlreadyExecuting    uint8 = 0x10 // requested operation already executing
	IIN2ConfigCorrupt       uint8 = 0x20 // configuration is corrupt
)

// ParseIIN extracts the two Internal Indications octets from a response
// APDU. `apdu` is the de-blocked user data:
//
//	[0] transport, [1] application control, [2] FC, [3] IIN1, [4] IIN2
//
// Returns ok=false when the APDU is not an outstation response
// (FC 0x81 / 0x82) or is too short to carry the IIN.
func ParseIIN(apdu []byte) (iin1, iin2 uint8, ok bool) {
	if len(apdu) < 5 {
		return 0, 0, false
	}
	fc := apdu[2]
	if fc != 0x81 && fc != 0x82 {
		return 0, 0, false
	}
	return apdu[3], apdu[4], true
}

// IINStateChange reports whether the IIN confirms the device changed
// state: it restarted, reported trouble, or has a corrupt
// configuration. These are the "something happened here" signals a
// defender wants surfaced immediately.
func IINStateChange(iin1, iin2 uint8) bool {
	return iin1&(IIN1DeviceRestart|IIN1DeviceTrouble) != 0 || iin2&IIN2ConfigCorrupt != 0
}

// IINError reports whether the IIN carries a per-response error bit
// (function-not-supported, object-unknown, parameter-error). A single
// one can be benign; a burst across a session is enumeration or
// fuzzing.
func IINError(iin2 uint8) bool {
	return iin2&(IIN2FuncNotSupp|IIN2ObjectUnknown|IIN2ParameterError) != 0
}

// IINBits returns the names of the notable IIN bits that are set, for
// logging. Routine bits (class-data available, need-time) are omitted:
// they are normal polling traffic, not a finding.
func IINBits(iin1, iin2 uint8) []string {
	var out []string
	for _, b := range []struct {
		mask uint8
		name string
	}{
		{IIN1DeviceRestart, "device_restart"},
		{IIN1DeviceTrouble, "device_trouble"},
		{IIN1LocalControl, "local_control"},
	} {
		if iin1&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	for _, b := range []struct {
		mask uint8
		name string
	}{
		{IIN2FuncNotSupp, "func_not_supported"},
		{IIN2ObjectUnknown, "object_unknown"},
		{IIN2ParameterError, "parameter_error"},
		{IIN2EventBufferOverflow, "event_buffer_overflow"},
		{IIN2ConfigCorrupt, "config_corrupt"},
	} {
		if iin2&b.mask != 0 {
			out = append(out, b.name)
		}
	}
	return out
}
