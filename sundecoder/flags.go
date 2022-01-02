package main
import "flag"

var piccData = flag.String("picc-data", "", "The actual PICCData (from PICCDataOffset)")
var macCode = flag.String("mac-code", "", "The MAC of the message")
var metaKeyData = flag.String("meta-read-key", "", "The key used for reading PICCData")
var fileKeyData = flag.String("file-read-key", "", "The key used for reading file data")
var macKeyData = flag.String("mac-key", "", "The key used for authenticating messages")
var macKeyApplicationData = flag.String("mac-key-application", "", "If set, this makes the MAC key a diversified key.  This is used as the application data for diversification.")
var usesLrpData = flag.Bool("use-lrp", false, "Set this flag to use LRP encryption")
