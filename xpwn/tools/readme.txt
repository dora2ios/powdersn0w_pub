# powdersn0w v3.0 alpha 4

!! test build !!

## support (hostside)
- macosx (intel)

## support (iosdevside)
- iPhone5,2 [(7.1,) 7.1.1, 7.1.2 iboot]

## included bundles
- 6.0
- 6.1.4
- 9.0.2
- 9.3.2
- 9.3.5


## IPSW
usage: ./ipsw <input.ipsw> <out.ipsw> -base <base.ipsw> -bbupdate [-memory]


## test/asr_patcher
INFO: ASR patcher
SUPPORT: ios 4.3-9.3.5 (??)
USAGE: ./asr_patcher <in> <out>


## test/iboot_patcher
INFO: iBoot (LLB/iBoot/iBSS/iBEC) patcher
SUPPORT: ios 5.0-9.3.5 (??)
USAGE: ./iboot_patcher <in_dec> <out_dec>


## test/kernel_patcher
INFO: Kernel Cache patcher
SUPPORT: ios 6.x, 9.x (??)
USAGE: ./kernel_patcher <in_dec> <out_dec>


At your own risk.
by dora2ios