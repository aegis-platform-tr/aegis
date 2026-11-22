//go:build windows

package tail

import "os"

// On Windows the file index requires an open handle (GetFileInformationByHandle). M2 uses
// the empty identity, so rotation is detected by truncation (size < offset) only.
// Documented limitation: a rename-and-recreate rotation to a larger file is not detected.
func fileID(_ os.FileInfo) string { return "" }
