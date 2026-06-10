#include "textflag.h"

// func outb(port uint16, val uint8)
TEXT ·outb(SB),NOSPLIT|NOFRAME,$0-3
	MOVW	port+0(FP), DX
	MOVB	val+2(FP), AX
	OUTB
	RET
