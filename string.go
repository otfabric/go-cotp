package cotp

import "fmt"

const maxBytesInString = 8 // show at most this many bytes of a slice in String()

// String returns a short debug representation of the parameter (code + value length or hex prefix).
func (p Parameter) String() string {
	if len(p.Value) == 0 {
		return fmt.Sprintf("0x%02X=[]", p.Code)
	}
	if len(p.Value) <= maxBytesInString {
		return fmt.Sprintf("0x%02X=%x", p.Code, p.Value)
	}
	return fmt.Sprintf("0x%02X=%x...(%d)", p.Code, p.Value[:maxBytesInString], len(p.Value))
}

// String returns a short debug representation of the CR TPDU for logging.
func (c *CR) String() string {
	if c == nil {
		return "CR(nil)"
	}
	s := fmt.Sprintf("CR{CDT:%d DST:%d SRC:%d Class:%d", c.CDT, c.DestinationRef, c.SourceRef, c.ClassOption)
	if c.CallingSelector != nil {
		s += fmt.Sprintf(" calling:%x", truncHex(c.CallingSelector))
	}
	if c.CalledSelector != nil {
		s += fmt.Sprintf(" called:%x", truncHex(c.CalledSelector))
	}
	if c.TPDUSize != nil {
		s += fmt.Sprintf(" size:%d", *c.TPDUSize)
	}
	if len(c.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(c.Parameters))
	}
	return s + "}"
}

// String returns a short debug representation of the CC TPDU for logging.
func (c *CC) String() string {
	if c == nil {
		return "CC(nil)"
	}
	s := fmt.Sprintf("CC{CDT:%d DST:%d SRC:%d Class:%d", c.CDT, c.DestinationRef, c.SourceRef, c.ClassOption)
	if c.CallingSelector != nil {
		s += fmt.Sprintf(" calling:%x", truncHex(c.CallingSelector))
	}
	if c.CalledSelector != nil {
		s += fmt.Sprintf(" called:%x", truncHex(c.CalledSelector))
	}
	if c.TPDUSize != nil {
		s += fmt.Sprintf(" size:%d", *c.TPDUSize)
	}
	if len(c.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(c.Parameters))
	}
	return s + "}"
}

// String returns a short debug representation of the DT TPDU for logging.
func (d *DT) String() string {
	if d == nil {
		return "DT(nil)"
	}
	s := fmt.Sprintf("DT{EOT:%v", d.EOT)
	if d.TPDUNR != nil {
		s += fmt.Sprintf(" NR:%d", *d.TPDUNR)
	}
	if d.DestinationRef != nil {
		s += fmt.Sprintf(" DST:%d", *d.DestinationRef)
	}
	if len(d.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(d.Parameters))
	}
	s += fmt.Sprintf(" userdata:%d", len(d.UserData))
	return s + "}"
}

// String returns a short debug representation of the DR TPDU for logging.
func (d *DR) String() string {
	if d == nil {
		return "DR(nil)"
	}
	s := fmt.Sprintf("DR{DST:%d SRC:%d Reason:%d", d.DestinationRef, d.SourceRef, d.Reason)
	if len(d.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(d.Parameters))
	}
	s += fmt.Sprintf(" userdata:%d", len(d.UserData))
	return s + "}"
}

// String returns a short debug representation of the DC TPDU for logging.
func (d *DC) String() string {
	if d == nil {
		return "DC(nil)"
	}
	s := fmt.Sprintf("DC{DST:%d SRC:%d", d.DestinationRef, d.SourceRef)
	if len(d.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(d.Parameters))
	}
	return s + "}"
}

// String returns a short debug representation of the ER TPDU for logging.
func (e *ER) String() string {
	if e == nil {
		return "ER(nil)"
	}
	s := fmt.Sprintf("ER{DST:%d Cause:%d", e.DestinationRef, e.RejectCause)
	if len(e.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(e.Parameters))
	}
	return s + "}"
}

// String returns a short debug representation of the ED TPDU for logging.
func (e *ED) String() string {
	if e == nil {
		return "ED(nil)"
	}
	s := "ED{"
	if e.DestinationRef != nil {
		s += fmt.Sprintf("DST:%d ", *e.DestinationRef)
	}
	if e.TPDUNR != nil {
		s += fmt.Sprintf("NR:%d ", *e.TPDUNR)
	}
	s += fmt.Sprintf("EOT:%v ", e.EOT)
	if len(e.Parameters) > 0 {
		s += fmt.Sprintf("params:%d ", len(e.Parameters))
	}
	s += fmt.Sprintf("userdata:%d}", len(e.UserData))
	return s
}

// String returns a short debug representation of the AK TPDU for logging.
func (a *AK) String() string {
	if a == nil {
		return "AK(nil)"
	}
	s := fmt.Sprintf("AK{CDT:%d DST:%d YRTUNR:%d", a.CDT, a.DestinationRef, a.YRTUNR)
	if len(a.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(a.Parameters))
	}
	return s + "}"
}

// String returns a short debug representation of the EA TPDU for logging.
func (e *EA) String() string {
	if e == nil {
		return "EA(nil)"
	}
	s := fmt.Sprintf("EA{DST:%d YREDTUNR:%d", e.DestinationRef, e.YREDTUNR)
	if len(e.Parameters) > 0 {
		s += fmt.Sprintf(" params:%d", len(e.Parameters))
	}
	return s + "}"
}

// String returns a short debug representation of the RJ TPDU for logging.
func (r *RJ) String() string {
	if r == nil {
		return "RJ(nil)"
	}
	return fmt.Sprintf("RJ{CDT:%d DST:%d YRTUNR:%d}", r.CDT, r.DestinationRef, r.YRTUNR)
}

func truncHex(b []byte) []byte {
	if len(b) <= maxBytesInString {
		return b
	}
	return b[:maxBytesInString]
}
