#ICC		= xcrun -sdk iphoneos clang
MCC		= clang
MCC_FLAGS	= -I../include -Os -Wall -Dunix
.PHONY: all

all:
	$(MCC) $(MCC_FLAGS) -c *.c
	ar rcs minizip.a *.o
	-$(RM) *.o


clean:
	-$(RM) *.o *.a
