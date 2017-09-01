default: all
all: aesDefault aesCtr aesAnyLength

aesDefault: 
	gcc –w test.c TI_aes.c -o aesDefault

aesCtr:
	gcc –w test_ctr.c counterMode.c TI_aes.c -o aesCtr -lm

aesAnyLength:
	gcc -w test_any_length.c aes_any_length.c TI_aes.c -o aesAnyLength -lm

clean:
	rm -f *.o aesDefault aesCtr aesAnyLength
