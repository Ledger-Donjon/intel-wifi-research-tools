CFLAGS := -mcpu=arc700 -fomit-frame-pointer -Wall -O3

all: payload-lmac.bin payload-umac.bin prologue.bin test redirect.bin
	arc-elf32-objdump -b elf32-littlearc --disassemble=blah payload-lmac.o
	arc-elf32-objdump -b elf32-littlearc --disassemble=blah payload-umac.o

test: test.c
	arc-elf32-gcc $(CFLAGS) -o $@ $^

payload-lmac.o: payload.c
	arc-elf32-gcc $(CFLAGS) -D LMAC -c -o $@ $^

payload-umac.o: payload.c
	arc-elf32-gcc $(CFLAGS) -D UMAC -c -o $@ $^

payload-%.bin: payload-%.o
	arc-elf32-objcopy -O binary $^ $@

%.bin: %.o
	arc-elf32-objcopy -O binary $^ $@

%.o: %.s
	arc-elf32-as -o $@ $^
	arc-elf32-objdump -D --disassemble=entry -m arc700 $@

clean:
	rm -f *.o *.bin
