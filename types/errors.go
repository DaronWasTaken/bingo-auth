package types

type APIError struct {
	Code int
	Text string
}

func (e APIError) Error() string {
	return e.Text
}