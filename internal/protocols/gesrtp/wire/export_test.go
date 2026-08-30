package wire

// GEPLCFamilyPrefixes exposes the internal canonical GE PLC model
// prefix list to the external _test package. Tests validate
// ExtractModelHint's output against the REAL, current list rather than
// a hand-copied subset that silently goes stale as the list grows
// (the v2.47 additions, e.g. "PAC9000", are exactly what a stale copy
// missed).
var GEPLCFamilyPrefixes = gePLCFamilyPrefixes
