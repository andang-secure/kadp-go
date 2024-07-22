package kadp

type Mode string

const (
	CBC Mode = "CBC"
	ECB Mode = "ECB"
	CTR Mode = "CTR"
	CFB Mode = "CFB"
	OFB Mode = "OFB"
	CGM Mode = "CGM"
)
