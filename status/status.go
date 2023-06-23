package status

type Exception struct {
	ErrorCode int
	ErrorMsg  string
}

func NewError(code int, msg string) *Exception {
	return &Exception{
		ErrorCode: code,
		ErrorMsg:  msg,
	}
}

func (e *Exception) Error() string {
	return e.ErrorMsg
}
