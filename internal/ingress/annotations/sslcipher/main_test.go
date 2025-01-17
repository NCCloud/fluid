/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package sslcipher

import (
	"testing"

	"github.com/NCCloud/fluid/internal/ingress/annotations/parser"
	"github.com/NCCloud/fluid/internal/ingress/resolver"
	api "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestParse(t *testing.T) {
	annotation := parser.GetAnnotationWithPrefix("ssl-ciphers")
	ap := NewParser(&resolver.Mock{})
	if ap == nil {
		t.Fatalf("expected a parser.IngressAnnotation but returned nil")
	}

	testCases := []struct {
		annotations map[string]string
		expected    string
	}{
		{map[string]string{annotation: "ALL:!aNULL:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"}, "ALL:!aNULL:!EXPORT56:RC4+RSA:+HIGH:+MEDIUM:+LOW:+SSLv2:+EXP"},
		{map[string]string{annotation: "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"},
			"ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256"},
		{map[string]string{annotation: ""}, ""},
		{map[string]string{}, ""},
		{nil, ""},
	}

	ing := &extensions.Ingress{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "foo",
			Namespace: api.NamespaceDefault,
		},
		Spec: extensions.IngressSpec{},
	}

	for _, testCase := range testCases {
		ing.SetAnnotations(testCase.annotations)
		result, _ := ap.Parse(ing)
		if result != testCase.expected {
			t.Errorf("expected %v but returned %v, annotations: %s", testCase.expected, result, testCase.annotations)
		}
	}
}
