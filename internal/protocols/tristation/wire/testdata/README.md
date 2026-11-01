# TriStation test vectors

`cp_status_response.hex` is the UDP payload of one controller reply
(TCM COMMAND REPLY carrying TriStation command 108, "Get CP status
response") taken from `malware_exec.pcap` in NozomiNetworks/tricotools
(BSD 3-Clause, Copyright (c) 2018, Nozomi Networks). Only the UDP
payload is kept: no addresses or link-layer data. The connect,
disconnect and Get CP status request vectors in `wire_test.go` come from
the same capture.
