// Package codesys implements the ElSereno plugin for CoDeSys V3
// (3S-Smart / CoDeSys GmbH) on TCP/1217. The default build is
// read-only: a 4-byte BlockDriver magic hello is sent and the
// response classified by either the BlockDriver magic echo or
// the presence of canonical CoDeSys banner substrings. No
// service-request APDUs are issued.
package codesys
