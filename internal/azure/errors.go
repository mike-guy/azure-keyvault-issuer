package azure

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// maxMessageLength bounds the service message kept in errorText, so that a
// condition or event stays readable.
const maxMessageLength = 300

// errorText returns err's message with any Azure response error shortened to
// one line, such as "HTTP 403 Forbidden (ForbiddenByRbac): Caller is not
// authorized...". The SDK's own text spans many lines and repeats the request
// and response, which suits logs but not issuer conditions and events. A
// failed Entra token request is shortened the same way, as "authentication
// failed: HTTP 400 Bad Request (invalid_request): AADSTS...". The context
// added by wrapping is kept.
func errorText(err error) string {
	if err == nil {
		return ""
	}

	text := err.Error()

	var re *azcore.ResponseError
	if errors.As(err, &re) {
		code, msg := serviceError(re.RawResponse)
		if code == "" {
			code = re.ErrorCode
		}

		return strings.Replace(text, re.Error(), shortHTTPError(re.StatusCode, code, msg), 1)
	}

	var afe *azidentity.AuthenticationFailedError
	if errors.As(err, &afe) && afe.RawResponse != nil {
		code, msg := entraError(afe.RawResponse)
		short := "authentication failed: " + shortHTTPError(afe.RawResponse.StatusCode, code, msg)

		return strings.Replace(text, afe.Error(), short, 1)
	}

	return text
}

// shortError keeps err's chain but reports it with errorText's one-line text.
type shortError struct {
	err error
}

func (e shortError) Error() string { return errorText(e.err) }

func (e shortError) Unwrap() error { return e.err }

// Shorten wraps an error returned by an Azure SDK call so that its message is
// one line, while errors.As and errors.Is still reach the SDK's own error.
// issuer-lib copies Error() into conditions and events, so call Shorten where
// the SDK call returns, before adding context with %w.
func Shorten(err error) error {
	if err == nil {
		return nil
	}

	return shortError{err: err}
}

// StatusCode returns the HTTP status code of the Azure response error in
// err's chain, if there is one. A failed Entra token request counts too:
// azidentity reports it as an AuthenticationFailedError rather than a
// ResponseError, so a throttled or failing token endpoint would otherwise
// look like a permanent failure.
func StatusCode(err error) (int, bool) {
	var re *azcore.ResponseError
	if errors.As(err, &re) {
		return re.StatusCode, true
	}

	var afe *azidentity.AuthenticationFailedError
	if errors.As(err, &afe) && afe.RawResponse != nil {
		return afe.RawResponse.StatusCode, true
	}

	return 0, false
}

func shortHTTPError(status int, code, msg string) string {
	text := fmt.Sprintf("HTTP %d %s", status, http.StatusText(status))
	if code != "" {
		text += " (" + code + ")"
	}

	if msg != "" {
		text += ": " + msg
	}

	return text
}

// serviceError extracts the most specific error code and the message from an
// Azure service's error body, in the standard shape that Key Vault, ARM and
// most other Azure REST APIs share. The inner code is preferred because it
// says why a request was refused, for example ForbiddenByRbac rather than
// Forbidden.
func serviceError(resp *http.Response) (code, msg string) {
	var payload struct {
		Error struct {
			Message    string `json:"message"`
			InnerError struct {
				Code string `json:"code"`
			} `json:"innererror"`
		} `json:"error"`
	}
	if !decodeBody(resp, &payload) {
		return "", ""
	}

	return payload.Error.InnerError.Code, oneLine(payload.Error.Message)
}

// entraError extracts the error code and description from an Entra token
// endpoint's OAuth 2.0 error body. The description starts with the AADSTS
// code that identifies the cause.
func entraError(resp *http.Response) (code, msg string) {
	var payload struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if !decodeBody(resp, &payload) {
		return "", ""
	}

	return payload.Error, oneLine(payload.Description)
}

// decodeBody decodes resp's JSON body into v, reporting whether it could.
func decodeBody(resp *http.Response, v any) bool {
	if resp == nil {
		return false
	}

	body, err := runtime.Payload(resp)
	if err != nil {
		return false
	}

	return json.Unmarshal(body, v) == nil
}

// oneLine collapses msg's whitespace, newlines included, and bounds its
// length to maxMessageLength.
func oneLine(msg string) string {
	msg = strings.Join(strings.Fields(msg), " ")
	if r := []rune(msg); len(r) > maxMessageLength {
		msg = string(r[:maxMessageLength]) + "..."
	}

	return msg
}
