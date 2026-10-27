// Package tristation implements the ElSereno plugin for TriStation, the
// Schneider Electric (Triconex) engineering protocol spoken by Tricon
// safety instrumented systems on UDP/1502. TRITON/TRISIS used it in 2017
// to reprogram a safety controller.
//
// A safety controller is the last layer that keeps a plant from hurting
// people, so the plugin is OPT-IN (DefaultPort 0) and never part of the
// default sweep. Its probe sends one TCM CONNECT REQUEST, classifies the
// reply and sends DISCONNECT: no TriStation command is issued. The
// `elsereno tristation --active --status` verb adds one read-only "Get
// CP status" command; `--passive` decodes a capture offline and touches
// no network. Frame layout and checksums are validated against the
// public TRITON capture (wire/testdata/README.md).
package tristation
