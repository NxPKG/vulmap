package structs

import (
	_ "embed"

	"github.com/khulnasoft-lab/gostruct"
)

// StructsUnpack the byte slice (presumably packed by Pack(format, msg)) according to the given format.
// The result is a []interface{} slice even if it contains exactly one item.
// The byte slice must contain not less the amount of data required by the format
// (len(msg) must more or equal CalcSize(format)).
// Ex: structs.Unpack(">I", buff[:nb])
func Unpack(format string, msg []byte) ([]interface{}, error) {
	return gostruct.UnPack(buildFormatSliceFromStringFormat(format), msg)
}

// StructsPack returns a byte slice containing the values of msg slice packed according to the given format.
// The items of msg slice must match the values required by the format exactly.
// Ex: structs.pack("H", 0)
func Pack(formatStr string, msg interface{}) ([]byte, error) {
	var args []interface{}
	switch v := msg.(type) {
	case []interface{}:
		args = v
	default:
		args = []interface{}{v}
	}
	format := buildFormatSliceFromStringFormat(formatStr)

	for i, f := range format {
		if i >= len(args) {
			break
		}
		switch f {
		case "h", "H", "i", "I", "l", "L", "q", "Q", "b", "B":
			switch v := args[i].(type) {
			case int64:
				args[i] = int(v)
			}
		}
	}
	return gostruct.Pack(format, args)
}

// StructsCalcSize returns the number of bytes needed to pack the values according to the given format.
func StructsCalcSize(format string) (int, error) {
	return gostruct.CalcSize(buildFormatSliceFromStringFormat(format))
}

func buildFormatSliceFromStringFormat(format string) []string {
	var formats []string
	temp := ""

	for _, c := range format {
		if c >= '0' && c <= '9' {
			temp += string(c)
		} else {
			if temp != "" {
				formats = append(formats, temp+string(c))
				temp = ""
			} else {
				formats = append(formats, string(c))
			}
		}
	}
	if temp != "" {
		formats = append(formats, temp)
	}
	return formats
}
