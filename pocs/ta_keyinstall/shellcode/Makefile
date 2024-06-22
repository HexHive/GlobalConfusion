
shellcode: shellcode.S
	arm-none-eabi-gcc -march=armv7-a -c shellcode.S -o shellcode
	arm-none-eabi-objcopy -O binary shellcode shellcode.bin
	#$ARM_EABI_PATH/arm-eabi-objdump -D -b binary -m arm -EL -M force-thumb shellcode.bin
	#$ARM_EABI_PATH/arm-eabi-objdump -d shellcode

