package apperr

import (
	"errors"
	"fmt"
)

type FormatError struct{ Err error }

func (e *FormatError) Error() string { return e.Err.Error() }
func (e *FormatError) Unwrap() error { return e.Err }

type InputError struct{ Err error }

func (e *InputError) Error() string { return e.Err.Error() }
func (e *InputError) Unwrap() error { return e.Err }

func Format(format string, a ...any) error {
	return &FormatError{Err: fmt.Errorf(format, a...)}
}

func Input(format string, a ...any) error {
	return &InputError{Err: fmt.Errorf(format, a...)}
}

func WrapInput(err error) error {
	if err == nil {
		return nil
	}
	var ie *InputError
	if errors.As(err, &ie) {
		return err
	}
	return &InputError{Err: err}
}

func WrapFormat(err error) error {
	if err == nil {
		return nil
	}
	var fe *FormatError
	if errors.As(err, &fe) {
		return err
	}
	return &FormatError{Err: err}
}

func IsFormat(err error) bool {
	var fe *FormatError
	return errors.As(err, &fe)
}

func IsInput(err error) bool {
	var ie *InputError
	return errors.As(err, &ie)
}
