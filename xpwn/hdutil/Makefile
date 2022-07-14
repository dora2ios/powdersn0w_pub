#ICC		= xcrun -sdk iphoneos clang
MCC		= clang
MCC_FLAGS	= -I../include -Os -Wall
.PHONY: all

all:
	$(MCC) $(MCC_FLAGS) -c *.c
	ar rcs hdutil.a *.o
	-$(RM) *.o


clean:
	-$(RM) *.o *.a
