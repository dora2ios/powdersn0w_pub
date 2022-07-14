#ICC		= xcrun -sdk iphoneos clang
MCC		= clang
MCC_FLAGS	= -I../include -Os -Wall 

.PHONY: all

all:
	$(MCC) $(MCC_FLAGS) -c bspatch.c
	$(MCC) $(MCC_FLAGS) -c ibootim.c 
	$(MCC) $(MCC_FLAGS) -c img3.c
	$(MCC) $(MCC_FLAGS) -c libxpwn.c
	$(MCC) $(MCC_FLAGS) -c lzss.c
	$(MCC) $(MCC_FLAGS) -c lzssfile.c
	$(MCC) $(MCC_FLAGS) -c nor_files.c
	$(MCC) $(MCC_FLAGS) -c outputstate.c -I../minizip
	$(MCC) $(MCC_FLAGS) -c plist.c
	$(MCC) $(MCC_FLAGS) -c pwnutil.c

	ar rcs xpwn.a *.o
	-$(RM) *.o


clean:
	-$(RM) *.o *.a
