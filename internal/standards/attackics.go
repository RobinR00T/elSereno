package standards

// attackICS is the MITRE ATT&CK for ICS release the technique IDs and
// names below were checked against (the ics-attack STIX bundle of
// mitre-attack/attack-stix-data, collection version 20.0, modified
// 2026-10-13). Revoked techniques (T0812 Default Credentials, T0855
// Unauthorized Command Message, T0856 Spoof Reporting Message, T0891
// Hardcoded Credentials) are not used.
const attackICS = "MITRE ATT&CK for ICS v20"

// ATT&CK for ICS references. For these the Ref fields read: Table = the
// technique ID, Vuln = the technique name. A mapping says "a finding for
// this protocol shows the exposure an adversary uses for this technique";
// it is elSereno's reading, not a statement by MITRE.
var (
	attRemoteSysInfo  = Ref{attackICS, "T0888", "Remote System Information Discovery"}
	attModifyParam    = Ref{attackICS, "T0836", "Modify Parameter"}
	attProgramDl      = Ref{attackICS, "T0843", "Program Download"}
	attChangeOpMode   = Ref{attackICS, "T0858", "Change Operating Mode"}
	attPointTagID     = Ref{attackICS, "T0861", "Point & Tag Identification"}
	attMonitorProcess = Ref{attackICS, "T0801", "Monitor Process State"}
	attExtRemoteSvc   = Ref{attackICS, "T0822", "External Remote Services"}
	attRemoteServices = Ref{attackICS, "T0886", "Remote Services"}
)

// attackRefs maps a plugin protocol name to the ATT&CK for ICS techniques
// its findings show exposure to. Every OT fingerprint reads device
// identity without authentication (T0888); protocols whose specification
// carries an unauthenticated write add T0836; engineering protocols that
// carry a program download add T0843. Telephony and X.25 plugins have no
// claimed mapping.
var attackRefs = map[string][]Ref{
	"s7":             {attRemoteSysInfo, attProgramDl},
	"s7-exposure":    {attRemoteSysInfo, attProgramDl, attChangeOpMode},
	"opcua":          {attRemoteSysInfo},
	"opcua-exposure": {attPointTagID, attModifyParam},
	"opcuahttps":     {attRemoteSysInfo},
	"modbus":         {attRemoteSysInfo, attModifyParam},
	"enip":           {attRemoteSysInfo, attModifyParam},
	"dnp3":           {attRemoteSysInfo, attModifyParam},
	"bacnet":         {attRemoteSysInfo, attModifyParam},
	"iec104":         {attRemoteSysInfo, attModifyParam},
	"mms":            {attRemoteSysInfo, attModifyParam},
	"finsudp":        {attRemoteSysInfo, attModifyParam},
	"slmp":           {attRemoteSysInfo, attModifyParam},
	"melsoft":        {attRemoteSysInfo, attProgramDl},
	"gesrtp":         {attRemoteSysInfo, attProgramDl},
	"knxip":          {attRemoteSysInfo, attModifyParam},
	"mbustcp":        {attRemoteSysInfo},
	"dlms":           {attRemoteSysInfo},
	"hartip":         {attRemoteSysInfo},
	"fox":            {attRemoteSysInfo},
	"pcworx":         {attRemoteSysInfo, attProgramDl},
	"proconos":       {attRemoteSysInfo, attProgramDl},
	"codesys":        {attRemoteSysInfo, attProgramDl},
	"codesys-active": {attRemoteSysInfo, attProgramDl},
	"redlion":        {attRemoteSysInfo},
	"twincat":        {attRemoteSysInfo, attProgramDl},
	"atg":            {attRemoteSysInfo, attModifyParam},
	"tristation":     {attRemoteSysInfo, attProgramDl, attChangeOpMode},
	"profinet-cm":    {attRemoteSysInfo},
	"mqtt":           {attMonitorProcess},
	"atmodem":        {attExtRemoteSvc},
	"cwmp":           {attExtRemoteSvc},
	"it-management":  {attRemoteServices},
}
