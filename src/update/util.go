package update

import (
	"fmt"
	"strconv"
)

func AddrbyteToString(bytes []byte, base int) string {
	str := ""
	for i, v := range bytes {
		var num uint8 = v
		if base == 16 {
			str += fmt.Sprintf("%02x", num)
		} else {
			str += strconv.FormatUint(uint64(num), base)

		}

		if i <= len(bytes)-2 {
			if base == 16 {
				str += ":"

			} else {

				str += "."
			}
		}

	}
	return str
}
