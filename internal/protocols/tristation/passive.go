package tristation

import (
	"sort"
	"time"

	"local/elsereno/internal/pcapfile"
	"local/elsereno/internal/protocols/tristation/wire"
)

// Event is one decoded TriStation datagram worth reporting.
type Event struct {
	Time    time.Time `json:"time"`
	Src     string    `json:"src"`
	Dst     string    `json:"dst"`
	Command byte      `json:"command"`
	Name    string    `json:"name"`
	// Change is true for commands that alter the safety program or the
	// controller's run state (download, run, halt, allocate, ...).
	Change bool `json:"change"`
}

// StatusSeen is a CP status the controller reported in the capture.
type StatusSeen struct {
	Time       time.Time     `json:"time"`
	Controller string        `json:"controller"`
	Status     wire.CPStatus `json:"status"`
}

// Report is the passive analysis of a capture.
type Report struct {
	Datagrams   int            `json:"datagrams"`
	TriStation  int            `json:"tristation_frames"`
	BadFrames   int            `json:"bad_frames"`
	Controllers []string       `json:"controllers"`
	Commands    map[string]int `json:"commands"`
	Changes     []Event        `json:"changes"`
	// Statuses lists each distinct CP status per controller, in order:
	// a controller polled every second reports one entry per change.
	Statuses []StatusSeen `json:"statuses"`
}

// Analyse decodes every UDP datagram to or from port 1502. It never
// touches the network.
func Analyse(ds []pcapfile.Datagram) Report {
	r := Report{Datagrams: len(ds), Commands: map[string]int{}}
	ctrl := map[string]bool{}
	last := map[string]wire.CPStatus{} // statuses are reported when they change
	for _, d := range ds {
		if d.Dst.Port() != wire.Port && d.Src.Port() != wire.Port {
			continue
		}
		f, err := wire.Parse(d.Payload)
		if err != nil {
			r.BadFrames++
			continue
		}
		r.TriStation++
		controller := d.Dst
		if d.Src.Port() == wire.Port {
			controller = d.Src
		}
		ctrl[controller.String()] = true
		if f.TS == nil {
			r.Commands[wire.OpcodeName(f.Opcode)]++
			continue
		}
		name := wire.CommandName(f.TS.Command)
		r.Commands[name]++
		if d.Dst.Port() == wire.Port && wire.IsChange(f.TS.Command) {
			r.Changes = append(r.Changes, Event{Time: d.Time, Src: d.Src.String(), Dst: d.Dst.String(),
				Command: f.TS.Command, Name: name, Change: true})
		}
		if st, err := wire.ParseCPStatus(d.Payload); err == nil && last[controller.String()] != st {
			last[controller.String()] = st
			r.Statuses = append(r.Statuses, StatusSeen{Time: d.Time, Controller: controller.String(), Status: st})
		}
	}
	for c := range ctrl {
		r.Controllers = append(r.Controllers, c)
	}
	sort.Strings(r.Controllers)
	return r
}
