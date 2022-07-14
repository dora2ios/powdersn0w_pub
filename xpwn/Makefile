#ICC		= xcrun -sdk iphoneos clang
MCC		= clang
MCC_FLAGS	= -I./include -Os -Wall -Ilib/openssl/include


STATIC		= */*.a static/x86_64/*.a

.PHONY: all test asr iboot kernel common dmg hdutil hfs minizip ipsw-patch build validate ticket daibutsu

all: asr iboot kernel common dmg hdutil hfs minizip ipsw-patch
	$(MCC) $(MCC_FLAGS) $(STATIC) ipsw-patch/main.c -o ipsw
	strip ipsw

validate: common minizip ipsw-patch
	$(MCC) $(MCC_FLAGS) $(STATIC) ipsw-patch/validate.c -o validate

ticket: common minizip ipsw-patch
	$(MCC) $(MCC_FLAGS) $(STATIC) ipsw-patch/ticket.c -o ticket

asr:
	cd asr && \
	make all && \
	cd ..

iboot:
	cd iboot && \
	make all && \
	cd ..

kernel:
	cd kernel && \
	make all && \
	cd ..

common:
	cd common && \
	make all && \
	cd ..

dmg:
	cd dmg && \
	make all && \
	cd ..

hdutil:
	cd hdutil && \
	make all && \
	cd ..

hfs:
	cd hfs && \
	make all && \
	cd ..

minizip:
	cd minizip && \
	make all && \
	cd ..

ipsw-patch:
	cd ipsw-patch && \
	make all && \
	cd ..

test: asr iboot kernel common hfs minizip ipsw-patch
	$(MCC) $(MCC_FLAGS) $(STATIC) tools/kernel_patcher.c -o tools/kernel_patcher
	strip tools/kernel_patcher
	$(MCC) $(MCC_FLAGS) $(STATIC) tools/iboot_patcher.c -o tools/iboot_patcher
	strip tools/iboot_patcher
	$(MCC) $(MCC_FLAGS) $(STATIC) tools/asr_patcher.c -o tools/asr_patcher
	strip tools/asr_patcher
	$(MCC) $(MCC_FLAGS) $(STATIC) tools/iboot_tester.c -o tools/iboot_tester
	strip tools/iboot_tester

build: all test
	-$(RM) -r build/*
	mkdir build/test/
	cp -a ipsw build/ipsw
	cp -a src build/
	cp -a FirmwareBundles build/
	cp -a tools/asr_patcher build/test/
	cp -a tools/iboot_patcher build/test/
	cp -a tools/kernel_patcher build/test/
	cp -a tools/readme.txt build/
	-$(RM) build/.DS_Store
	-$(RM) build/*/.DS_Store
	-$(RM) build/*/*/.DS_Store
	-$(RM) build/*/*/*/.DS_Store
	-$(RM) build/*/*/*/*/.DS_Store
	zip -r0 testbuild_v3.0_alpha4.zip build/
	mv testbuild_v3.0_alpha4.zip build/

daibutsu: asr iboot kernel common dmg hdutil hfs minizip ipsw-patch
	$(MCC) $(MCC_FLAGS) $(STATIC) ipsw-patch/daibutsu.c -o daibutsu
	strip daibutsu

clean:
	-$(RM) common/*.a common/*.o
	-$(RM) dmg/*.a dmg/*.o
	-$(RM) hdutil/*.a hdutil/*.o
	-$(RM) hfs/*.a hfs/*.o
	-$(RM) minizip/*.a minizip/*.o
	-$(RM) ipsw-patch/*.a ipsw-patch/*.o
	-$(RM) ipsw
	-$(RM) tools/kernel_patcher
	-$(RM) tools/iboot_patcher
	-$(RM) tools/asr_patcher
	-$(RM) -r build/*
	-$(RM) validate
	-$(RM) ticket
	-$(RM) daibutsu
