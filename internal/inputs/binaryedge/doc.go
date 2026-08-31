// Package binaryedge is a minimal BinaryEdge REST client for the
// v2 search API (https://api.binaryedge.io/v2/query/search). Same
// shape as the shodan / censys / fofa / zoomeye / onyphe clients: it
// authenticates with the account's X-Key header, runs an operator
// query, and returns only (ip, port) tuples as core.Target values;
// every other field BinaryEdge reports per event is intentionally
// ignored to keep the surface tight. Pagination accumulates across
// pages up to the caller's limit.
package binaryedge
