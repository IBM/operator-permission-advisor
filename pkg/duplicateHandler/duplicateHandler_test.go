/**
Copyright 2022 IBM

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

package duplicateHandler

import (
	"testing"
)

func TestDuplicateWrapper_CheckForDuplication(t *testing.T) {
	t1 := make(map[string]Hashable)
	t1h := &hashableFake{
		x: "test1",
	}
	t1[t1h.Hash()] = t1h

	t2 := make(map[string]Hashable)
	t2h := &hashableFake{
		x: "test",
	}
	t2[t2h.Hash()] = t2h
	type fields struct {
		HashMap map[string]Hashable
	}
	type args struct {
		h Hashable
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name: "test 1",
			fields: fields{
				HashMap: make(map[string]Hashable),
			},
			args: args{
				h: &hashableFake{
					x: "test",
				},
			},
			want: false,
		},
		{
			name: "test 2",
			fields: fields{
				HashMap: t1,
			},
			args: args{
				h: &hashableFake{
					x: "test",
				},
			},
			want: false,
		},
		{
			name: "test 3",
			fields: fields{
				HashMap: t2,
			},
			args: args{
				h: &hashableFake{
					x: "test",
				},
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DuplicateWrapper{
				HashMap: tt.fields.HashMap,
			}
			if got := d.CheckForDuplication(tt.args.h); got != tt.want {
				t.Errorf("DuplicateWrapper.CheckForDuplication() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDuplicateWrapper_RegisterDuplication(t *testing.T) {
	t1 := make(map[string]Hashable)
	t1h := &hashableFake{
		x: "test1",
	}
	t1[t1h.Hash()] = t1h

	t2 := make(map[string]Hashable)
	t2h := &hashableFake{
		x: "test",
	}
	t2[t2h.Hash()] = t2h
	type fields struct {
		HashMap map[string]Hashable
	}
	type args struct {
		h Hashable
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "test 1",
			fields: fields{
				HashMap: make(map[string]Hashable),
			},
			args: args{
				h: &hashableFake{
					x: "test",
				},
			},
			wantErr: false,
		},
		{
			name: "test 2",
			fields: fields{
				HashMap: t1,
			},
			args: args{
				h: &hashableFake{
					x: "test",
				},
			},
			wantErr: false,
		},
		{
			name: "test 3",
			fields: fields{
				HashMap: t2,
			},
			args: args{
				h: &hashableFake{
					x: "test",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DuplicateWrapper{
				HashMap: tt.fields.HashMap,
			}
			if err := d.RegisterDuplication(tt.args.h); (err != nil) != tt.wantErr {
				t.Errorf("DuplicateWrapper.RegisterDuplication() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
