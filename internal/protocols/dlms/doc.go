// Package dlms implements the ElSereno plugin for DLMS/COSEM
// over TCP per IEC 62056-46 (Green Book §8.4 — DLMS Wrapper)
// and IEC 62056-53 (COSEM application layer). Default port
// TCP/4059. The default build is read-only: a single AARQ
// (Application Association Request) is sent and the response
// classified by wrapper version + AARE tag presence. No
// GET-Request / SET-Request / ACTION-Request services are
// issued.
package dlms
