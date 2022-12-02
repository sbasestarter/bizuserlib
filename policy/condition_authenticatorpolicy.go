package policy

import (
	"context"
	"reflect"

	"github.com/sbasestarter/bizuserlib"
	"github.com/sbasestarter/bizuserlib/bizuserinters"
	"github.com/sgostarter/libexpression"
)

// DefaultConditionAuthenticatorPolicy .
// nolint: funlen
func DefaultConditionAuthenticatorPolicy() bizuserlib.Policy {
	key := reflect.TypeOf(bizuserinters.AuthenticatorEvent{}).Name()
	libexpression.UpdateOpValueTypeMap(key, reflect.TypeOf(bizuserinters.AuthenticatorEvent{}))

	conditions := make(map[bizuserinters.AuthenticatorEvent]*libexpression.Op)

	//
	// register
	//

	op := &libexpression.Op{
		OpType: libexpression.OpTypeAnd,
	}

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorUserPass,
			Event:         bizuserinters.RegisterEvent,
		},
	})

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorGoogle2FA,
			Event:         bizuserinters.RegisterEvent,
		},
	})

	conditions[bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.RegisterEvent,
	}] = op

	//
	// login
	//

	op = &libexpression.Op{
		OpType: libexpression.OpTypeAnd,
	}

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorUserPass,
			Event:         bizuserinters.VerifyEvent,
		},
	})

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorGoogle2FA,
			Event:         bizuserinters.VerifyEvent,
		},
	})

	conditions[bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUser,
		Event:         bizuserinters.VerifyEvent,
	}] = op

	//
	// change password
	//

	op = &libexpression.Op{
		OpType: libexpression.OpTypeAnd,
	}

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorUserPass,
			Event:         bizuserinters.VerifyEvent,
		},
	})

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorUserPass,
			Event:         bizuserinters.RegisterEvent,
		},
	})

	conditions[bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorUserPass,
		Event:         bizuserinters.ChangeEvent,
	}] = op

	//
	// change google2fa
	//

	op = &libexpression.Op{
		OpType: libexpression.OpTypeOr,
	}

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorUserPass,
			Event:         bizuserinters.VerifyEvent,
		},
	})

	op.Values = append(op.Values, &libexpression.Op{
		OpType:    libexpression.OpTypeValue,
		ValueType: key,
		Value: &bizuserinters.AuthenticatorEvent{
			Authenticator: bizuserinters.AuthenticatorGoogle2FA,
			Event:         bizuserinters.VerifyEvent,
		},
	})

	op = &libexpression.Op{
		OpType: libexpression.OpTypeAnd,
		Values: []*libexpression.Op{
			op,
			{
				OpType:    libexpression.OpTypeValue,
				ValueType: key,
				Value: &bizuserinters.AuthenticatorEvent{
					Authenticator: bizuserinters.AuthenticatorGoogle2FA,
					Event:         bizuserinters.RegisterEvent,
				},
			},
		},
	}

	conditions[bizuserinters.AuthenticatorEvent{
		Authenticator: bizuserinters.AuthenticatorGoogle2FA,
		Event:         bizuserinters.ChangeEvent,
	}] = op

	return NewConditionAuthenticatorPolicy(conditions)
}

func NewConditionAuthenticatorPolicy(conditions map[bizuserinters.AuthenticatorEvent]*libexpression.Op) bizuserlib.Policy {
	return &conditionAuthenticatorPolicy{
		conditions: conditions,
	}
}

type conditionAuthenticatorPolicy struct {
	conditions map[bizuserinters.AuthenticatorEvent]*libexpression.Op
}

func (impl *conditionAuthenticatorPolicy) Check(ctx context.Context, d bizuserlib.CheckPolicyData) (neededOrEvents []bizuserinters.AuthenticatorEvent, status bizuserinters.Status) {
	conditions, ok := impl.conditions[d.Purpose]
	if !ok {
		status.Code = bizuserinters.StatusCodeNotImplementError

		return
	}

	ops, r := libexpression.CheckEx(conditions, func(valueType string, value interface{}) libexpression.CheckResult {
		e, valid := value.(*bizuserinters.AuthenticatorEvent)
		if !valid {
			return libexpression.CheckResultInvalidLogic
		}

		for _, event := range d.DoneEvents {
			if event.Equal(*e) {
				return libexpression.CheckResultTrue
			}
		}

		return libexpression.CheckResultNeedOp
	})

	if r == libexpression.CheckResultNeedOp {
		for _, op := range ops {
			e, valid := op.Value.(*bizuserinters.AuthenticatorEvent)
			if !valid {
				status.Code = bizuserinters.StatusCodeLogicError

				return
			}

			neededOrEvents = append(neededOrEvents, *e)
		}

		status.Code = bizuserinters.StatusCodeNeedAuthenticator

		return
	}

	if r == libexpression.CheckResultTrue {
		status.Code = bizuserinters.StatusCodeOk

		return
	}

	status.Code = bizuserinters.StatusCodeLogicError

	return
}
