package domain

import "errors"

var (
	ErrThreatNotFound = errors.New("threat not found")
	ErrThreatExists   = errors.New("threat already exists")
	// ErrInvalidThreat reports data rejected by storage constraints that service
	// validation did not catch; it is a client error, not an internal one.
	ErrInvalidThreat = errors.New("threat violates storage constraints")
)
