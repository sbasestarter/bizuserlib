package bizuserinters

type StatusCode int

const (
	StatusCodeUnspecified StatusCode = iota
	StatusCodeOk
	StatusCodeNeedAuthenticator
	StatusCodeNotCompleted

	StatusCodeNoDataError
	StatusCodeInvalidArgsError
	StatusCodeInternalError
	StatusCodeExistsError
	StatusCodeNotImplementError
	StatusCodeConflictError
	StatusCodeExpiredError
	StatusCodeLogicError
	StatusCodeDupError
	StatusCodeVerifyError
	StatusCodeBadDataError
	StatusCodePermissionError
)

type Status struct {
	Code    StatusCode
	Message string
}

func MakeSuccessStatus() Status {
	return Status{
		Code: StatusCodeOk,
	}
}

func MakeStatusByCode(code StatusCode) Status {
	return Status{
		Code: code,
	}
}

func MakeStatusByError(code StatusCode, err error) Status {
	var msg string

	if err != nil {
		msg = err.Error()
	}

	return Status{
		Code:    code,
		Message: msg,
	}
}
