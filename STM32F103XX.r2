#structure of this file stolen from this talk by pancake:
#https://www.youtube.com/watch?v=oXSx0Qo2Upk
#
#Memory map information taken from STM32F103x[FG]
#datasheet at https://www.st.com/resource/en/datasheet/cd00253742.pdf
#Compiled and annotated by haystack (haystack@lavabit.com)
#map cleanups based on input from Ben Gardiner (https://twitter.com/BenLGardiner)

#remap the file at 0x8000000
#I'm pretty sure it's always mapid 1
omb 1 0x8000000

#configure the CPU
e asm.arch=arm
e asm.bits=16
e asm.cpu=cortex

#do strings analysis
e anal.strings=true

#go to vector table
s 0x8000000

#Show offsets in disasm prefixed with section/map name
e asm.section.sub = true

#keep aav out of our functions
e anal.vinfun = false

#allocate SRAM section
#on: map raw file @ address
on malloc://512M 0x20000000 rw
omn 0x20000000 SRAM

#allocate peripherals section
on malloc://512M 0x40000000 rw
omn 0x40000000 peripherals

#allocate FSMC sections
on malloc://512M 0x60000000 rw
omn 0x60000000 fsmc_bank_1_2
on malloc://512M 0x80000000 rw
omn 0x80000000 fsmc_bank_3_4
on malloc://512M 0xA0000000 rw
omn 0xA0000000 fsmc_bank_5

#allocate cortex peripherals section
on malloc://512M 0xE0000000 rw
omn 0xE0000000 cortex_peripherals

#define vector table addresses as data
#TODO: add ahp (probably need r2pipe) 
Cd 4 @@s:0x8000000 0x8000130 4


#place flags at base addrs of periphral registers
#TODO add useful Cortex peripherals
f TIM2 @ 0x40000000
f TIM3 @ 0x40000400
f TIM4 @ 0x40000800
f TIM5 @ 0x40000C00
f TIM6 @ 0x40001000
f TIM7 @ 0x40001400
f TIM12 @ 0x40001800
f TIM13 @ 0x40001C00
f TIM14 @ 0x40002000
f RTC @ 0x40002800
f WWDG @ 0x40002C00
f IWDG @ 0x40003000
f SPI2_I2S2 @ 0x40003800
f SPI3_I2S3 @ 0x40003C00
f USART2 @ 0x40004400
f USART3 @ 0x40004800
f USART4 @ 0x40004C00
f USART5 @ 0x40005000
f I2C1 @ 0x40005400
f I2C2 @ 0x40005800
f USB_reg @ 0x40005C00
f USB_CAN_SRAM @ 0x40006000
f BxCAN @ 0x40006400
f BKP @ 0x40006C00
f PWR @ 40007000
f DAC @ 0x40007400
f AFIO @ 0x40010000
f EXTI @ 0x40010400
f PORTA @ 0x40010800
f PORTB @ 0x40010C00
f PORTC @ 0x40011000
f PORTD @ 0x40011400
f PORTE @ 0x40011800
f PORTF @ 0x40011C00
f PORTG @ 0x40012000
f ADC1 @ 0x40012400
f ADC2 @ 0x40012800
f TIM1 @ 0x40012C00
f SPI1 @ 0x40013000
f TIM8 @ 0x40013400
f USART1 @ 0x40013800
f ADC3 @ 0x40013C00
f TIM9 @ 0x40014C00
f TIM10 @ 0x40015000
f TIM11 @ 0x40015400
f SDIO @ 0x40018000
f DMA1 @ 0x40020000
f DMA2 @ 0x40020400
f RCC @ 0x40021000
f FLASH_1_2 @ 0x40022000
f CRC @ 0x40023000
f FSMC_BANK_1_NOR_1 @ 0x60000000
f FSMC_BANK_1_NOR_2 @ 0x64000000
f FSMC_BANK_1_NOR_3 @ 0x68000000
f FSMC_BANK_1_NOR_4 @ 0x6C000000
f FSMC_BANK_2_NAND_1 @ 0x70000000
f FSMC_BANK_3_NAND_2 @ 0x80000000
f FSMC_BANK_4_PCCARD @ 0x90000000
f FSMC_reg @ 0xA0000000

#OK, one cortex peripheral
f SCB @ 0xE000ED00
f SCB_VTOR @ 0xE000ED08

#put this here so that a bunch of xrefs
#don't show up as SCB+840979753
f DUMMY @ 0xE000ED42
#also put a dummy for main peripherals
f DUMMY2 @ 0xA0001000

?e running autoanalysis
aaaa
?e Done!
