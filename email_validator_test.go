package fsa

import (
	"fmt"
	"testing"
)

func Test_EmailValidation(t *testing.T) {
	scenarios := []struct {
		email string
		valid bool
	}{
		{"", false},
		{"@example.com", false},
		{"plainaddress", false},
		{"email@domain@domain.com", false},
		{"email@domain..com", false},
		{"email@domain.com.", false},
		{"email@.com", false},
		{".email@domain.com", false},
		{"email@domain,com", false},
		{"email@domaincom", true},
		{"email@111.222.333.44444", true},
		{"email@domain..com", false},
		{"email@-domain.com", true},
		{"email@domain-.com", true},
		{"email@domain_.com", true},
		{"email.domain.com", false},
		{"email@domain+com", true},
		{"email@domain.com (Joe Smith)", true},
		{"email@domain", true},
		{"email@-domain.com", true},
		{"email@domain.web", true},
		{"email@localhost", true},
		{"email@123.123.123.123", true},
		{"email@[123.123.123.123]", false},
		{"username+mailbox@domain.com", true},
		{"customer/department@domain.com", true},
		{"$A12345@domain.com", true},
		{"!#$%&'*+-/=?^_`{|}~@domain.com", true},
		{"_______@domain.com", true},
		{"email@domain.name", true},
		{"email@domain.co.jp", true},
		{"firstname-lastname@domain.com", true},
	}
	for k, scenario := range scenarios {
		t.Run(fmt.Sprintf("%d", k), func(t *testing.T) {
			ev := NewEmailValidator()
			valid := ev.Validate(scenario.email)
			if valid != scenario.valid {
				t.Errorf("%s. Expected: %v, Actual: %v", scenario.email, scenario.valid, valid)
			}
		})
	}
}
