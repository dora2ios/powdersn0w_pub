#ICC		= xcrun -sdk iphoneos clang
MCC		= clang
MCC_FLAGS	= -I../include -Os -Wall  -DHAVE_CRYPT -I../lib/openssl/include

.PHONY: all

all:
	$(MCC) $(MCC_FLAGS) -c *.c
	ar rcs asr.a *.o
	-$(RM) *.o


clean:
	-$(RM) *.o *.a
