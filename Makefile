.PHONY: all all_dbg

CDIR := crackme_

all_dbg: ${CDIR}00/code.dbg.run ${CDIR}01/code.dbg.run
all:	 ${CDIR}00/code.run ${CDIR}01/code.run

${CDIR}%/code.dbg.run: ${CDIR}%/code.s
	nasm -f elf64 -O3 -g -o $^.o $^
	ld -o $@ $^.o
	rm $^.o

${CDIR}%/code.run: ${CDIR}%/code.s
	nasm -f elf64 -O3 -o $^.o $^
	ld -o $@ $^.o
	rm $^.o
	strip -s $@

clean:
	rm -rf ${CDIR}*/*.run
