package api

import "fmt"

// APIError is a client-side API error.
type APIError struct {
	Status  int
	Code    string
	Message string
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("api error %d (%s): %s", e.Status, e.Code, e.Message)
	}
	return fmt.Sprintf("api error %d: %s", e.Status, e.Message)
}
