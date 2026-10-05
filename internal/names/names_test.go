package names

import "testing"

func TestPathNames(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"myapp", true},
		{"my-app_2.0", true},
		{"0app", true},
		{"dev", true},
		{"", false},
		{"MyApp", false},
		{".hidden", false},
		{"-flag", false},
		{"_app", false},
		{"a..b", false},
		{"..", false},
		{"a/b", false},
		{`a\b`, false},
		{"a b", false},
		{"a\x00b", false},
		{"app\n", false},
		{"c:app", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Project(c.name); (err == nil) != c.ok {
				t.Errorf("Project(%q) error = %v, want ok = %v", c.name, err, c.ok)
			}
			if err := Environment(c.name); (err == nil) != c.ok {
				t.Errorf("Environment(%q) error = %v, want ok = %v", c.name, err, c.ok)
			}
		})
	}
}

func TestKey(t *testing.T) {
	cases := []struct {
		name string
		ok   bool
	}{
		{"API_KEY", true},
		{"_private", true},
		{"lower_case1", true},
		{"", false},
		{"1KEY", false},
		{"API-KEY", false},
		{"API KEY", false},
		{"KEY=1", false},
		{"KEY\n", false},
		{"KEY\x00", false},
		{"ÄPI", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Key(c.name); (err == nil) != c.ok {
				t.Errorf("Key(%q) error = %v, want ok = %v", c.name, err, c.ok)
			}
		})
	}
}
