/* UniDOS emulator */
/* By Nguyen Anh Quynh, 2015 */

#include <unicorn/unicorn.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <assert.h>

#include <stddef.h> // offsetof()

#include "ints/ints.h"
#include "global.h"
#include "psp.h"

// Experimentally found for mtkflash.exe
#define DOS_ADDR (0x10000-0x200)


static void usage(char* prog)
{
    printf("UniDOS for DOS emulation. Based on Unicorn engine (www.unicorn-engine.org)\n");
    printf("Syntax: %s <COM>\n", prog);
}

// callback for tracing instruction
static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    int eflags;

    uint16_t r_cs;
    uint16_t r_ip;
    uint8_t r_ah;

    uc_reg_read(uc, UC_X86_REG_CS, &r_cs);
    uc_reg_read(uc, UC_X86_REG_IP, &r_ip);

#if 0
    printf("                                >> @ 0x%X (0x%04X:%04X), size = 0x%x\n", address, r_cs, r_ip, size);
#endif

    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    //printf(">>> --- EFLAGS is 0x%x\n", eflags);

    // Uncomment below code to stop the emulation using uc_emu_stop()
    // if (address == 0x1000009)
    //    uc_emu_stop(uc);
}

// callback for handling interrupt
void hook_intr(uc_engine* uc, uint32_t intno, void* user_data)
{
    uint16_t r_cs;
    uint16_t r_ip;
    uint8_t r_ah;

    uc_reg_read(uc, UC_X86_REG_CS, &r_cs);
    uc_reg_read(uc, UC_X86_REG_IP, &r_ip);
    uc_reg_read(uc, UC_X86_REG_AH, &r_ah);

    // only handle DOS interrupt
printf("\n\n");
    switch(intno) {
        default:
            break;
        case 0x05:
            break;
        case 0x10:
            int10();
            break;
        case 0x15:
            int15();
            break;
        case 0x21:
            int21();
            break;
        case 0x20:
            int20();
            break;
        case 0x1a:
            //WTF?
            if (r_ah == 0) {
              r_ah = 0;
              uc_reg_write(uc, UC_X86_REG_AH, &r_ah);
              uc_reg_write(uc, UC_X86_REG_CX, &r_ah);
              uc_reg_write(uc, UC_X86_REG_DX, &r_ah);
            }
            break;
    }
#if 1
    uint16_t r_dx;
    uint32_t r_eflags;
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &r_eflags);
    uc_reg_read(uc, UC_X86_REG_DX, &r_dx);
    printf(">>> 0x%04X:%04X interrupt: 0x%X, function 0x%X [CF: %d; DX: 0x%04X]\n", r_cs, r_ip, intno, r_ah, r_eflags & 1, r_dx);
#endif
}

// callback for IN instruction (X86).
// this returns the data read from the port
static uint32_t hook_in(uc_engine *uc, uint32_t port, int size, void *user_data)
{
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- reading from port 0x%x, size: %u, address: 0x%x\n", port, size, eip);

    // IDE status

    if (port == 0x1F3) {
      //FIXME: What the fuck? Reading LBAlo
      return 0xFF;
    } else if (port == 0x1F7) {

      static int t = 0;
      t++;

      uint8_t status = 0x00;
      status |= 1 << 6; // Ready
      status |= 1 << 7; // Busy

      // 0x70 appears to be magic:
      // - 0x10 SRV 	Overlapped Mode Service Request.
      // - 0x20 DF 	Drive Fault Error (does not set ERR).
      // - 0x40 RDY 	Bit is clear when drive is spun down, or after an error. Set otherwise. 

if (t > 3) {
status = 0x70;
}

#if 0

      printf("Getting 0x%02X\n", t);
      return t++;
#endif

      return status;
    }

/*
Port: 1f0, Master/Slave: a0

// Set target drive
--- writing to port 0x1f6, size: 1, value: 0xa0, address: 0x118b7
--- reading from port 0x1f7, size: 1, address: 0x118bf

// LBAlo [flash pattern start]
--- writing to port 0x1f3, size: 1, value: 0x2a, address: 0x118ee

// ATA Command: Vendor specific
--- writing to port 0x1f7, size: 1, value: 0x80, address: 0x118f8

// Now it checks status again?
--- reading from port 0x1f7, size: 1, address: 0x12924

// Sector count
--- writing to port 0x1f2, size: 1, value: 0x15, address: 0x119cc

// 0x5555 = A {
{

  // LBAhi [flash pattern continue]
  --- writing to port 0x1f5, size: 1, value: 0x55, address: 0x119dc

  // LBAmid [flash pattern continue]
  --- writing to port 0x1f4, size: 1, value: 0x55, address: 0x119e9


--- reading from port 0x1f7, size: 1, address: 0x11875



// Retrieve latest stdin crap
>>> 0x1000:7D6F interrupt: 0x21, function 0xB [CF: 0; DX: 0x01F7]
>>> 0x1000:7B51 interrupt: 0x21, function 0x7 [CF: 0; DX: 0x01F7]




--- writing to port 0x1f6, size: 1, value: 0xa0, address: 0x1186d
--- reading from port 0x1f7, size: 1, address: 0x11875

  --- writing to port 0x1f3, size: 1, value: 0xaa, address: 0x11a08
}



0x2AAA = 0x55 {
  --- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11a15
  --- writing to port 0x1f2, size: 1, value: 0x40, address: 0x11a22
  --- writing to port 0x1f2, size: 1, value: 0x42, address: 0x11a2f
  --- writing to port 0x1f2, size: 1, value: 0x1, address: 0x11a3c
  --- writing to port 0x1f2, size: 1, value: 0x15, address: 0x119cc
  --- writing to port 0x1f5, size: 1, value: 0x2a, address: 0x119dc
  --- writing to port 0x1f4, size: 1, value: 0xaa, address: 0x119e9
  --- reading from port 0x1f7, size: 1, address: 0x11875
  --- writing to port 0x1f3, size: 1, value: 0x55, address: 0x11a08
}


[Flash product id exit]
0x5555 = 0xF0 {
  --- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11a15
  --- writing to port 0x1f2, size: 1, value: 0x40, address: 0x11a22
  --- writing to port 0x1f2, size: 1, value: 0x42, address: 0x11a2f
  --- writing to port 0x1f2, size: 1, value: 0x1, address: 0x11a3c
  --- writing to port 0x1f2, size: 1, value: 0x15, address: 0x119cc
  --- writing to port 0x1f5, size: 1, value: 0x55, address: 0x119dc
  --- writing to port 0x1f4, size: 1, value: 0x55, address: 0x119e9
  --- reading from port 0x1f7, size: 1, address: 0x11875
  --- writing to port 0x1f3, size: 1, value: 0xf0, address: 0x11a08
}

0x5555 = 0xAA {
  --- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11a15
  --- writing to port 0x1f2, size: 1, value: 0x40, address: 0x11a22
  --- writing to port 0x1f2, size: 1, value: 0x42, address: 0x11a2f
  --- writing to port 0x1f2, size: 1, value: 0x1, address: 0x11a3c
  --- writing to port 0x1f2, size: 1, value: 0x15, address: 0x119cc
  --- writing to port 0x1f5, size: 1, value: 0x55, address: 0x119dc
  --- writing to port 0x1f4, size: 1, value: 0x55, address: 0x119e9
  --- reading from port 0x1f7, size: 1, address: 0x11875
  --- writing to port 0x1f3, size: 1, value: 0xaa, address: 0x11a08
}

0x2AAA = 0x55 {
  --- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11a15
  --- writing to port 0x1f2, size: 1, value: 0x40, address: 0x11a22
  --- writing to port 0x1f2, size: 1, value: 0x42, address: 0x11a2f
  --- writing to port 0x1f2, size: 1, value: 0x1, address: 0x11a3c
  --- writing to port 0x1f2, size: 1, value: 0x15, address: 0x119cc
  --- writing to port 0x1f5, size: 1, value: 0x2a, address: 0x119dc
  --- writing to port 0x1f4, size: 1, value: 0xaa, address: 0x119e9
  --- reading from port 0x1f7, size: 1, address: 0x11875
  --- writing to port 0x1f3, size: 1, value: 0x55, address: 0x11a08
}

[Flash product id enter]
0x5555 = 0x90 {
  --- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11a15
  --- writing to port 0x1f2, size: 1, value: 0x40, address: 0x11a22
  --- writing to port 0x1f2, size: 1, value: 0x42, address: 0x11a2f
  --- writing to port 0x1f2, size: 1, value: 0x1, address: 0x11a3c
  --- writing to port 0x1f2, size: 1, value: 0x15, address: 0x119cc
  --- writing to port 0x1f5, size: 1, value: 0x55, address: 0x119dc
  --- writing to port 0x1f4, size: 1, value: 0x55, address: 0x119e9
  --- reading from port 0x1f7, size: 1, address: 0x11875
  --- writing to port 0x1f3, size: 1, value: 0x90, address: 0x11a08
}

--- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11a15
--- writing to port 0x1f2, size: 1, value: 0x40, address: 0x11a22
--- writing to port 0x1f2, size: 1, value: 0x42, address: 0x11a2f
--- writing to port 0x1f2, size: 1, value: 0x1, address: 0x11a3c
--- writing to port 0x1f2, size: 1, value: 0x15, address: 0x11954
--- writing to port 0x1f5, size: 1, value: 0x0, address: 0x11964
--- writing to port 0x1f4, size: 1, value: 0x0, address: 0x11971
--- reading from port 0x1f7, size: 1, address: 0x11875
--- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11992
--- writing to port 0x1f2, size: 1, value: 0x8, address: 0x1199f
--- reading from port 0x1f3, size: 1, address: 0x119a7

--- writing to port 0x1f2, size: 1, value: 0x15, address: 0x11954
--- writing to port 0x1f5, size: 1, value: 0x0, address: 0x11964
--- writing to port 0x1f4, size: 1, value: 0x1, address: 0x11971
--- reading from port 0x1f7, size: 1, address: 0x11875
--- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11992
--- writing to port 0x1f2, size: 1, value: 0x8, address: 0x1199f
--- reading from port 0x1f3, size: 1, address: 0x119a7

--- writing to port 0x1f2, size: 1, value: 0x15, address: 0x11954
--- writing to port 0x1f5, size: 1, value: 0x0, address: 0x11964
--- writing to port 0x1f4, size: 1, value: 0x3, address: 0x11971
--- reading from port 0x1f7, size: 1, address: 0x11875
--- writing to port 0x1f2, size: 1, value: 0x20, address: 0x11992
--- writing to port 0x1f2, size: 1, value: 0x8, address: 0x1199f
--- reading from port 0x1f3, size: 1, address: 0x119a7

*/

    // ???
    if (port == 0x40) {
      return 0xFF;
    }

    assert(false);

    switch(size) {
        default:
            return 0;   // should never reach this
        case 1:
            // read 1 byte to AL
            return 0xf1;
        case 2:
            // read 2 byte to AX
            return 0xf2;
            break;
        case 4:
            // read 4 byte to EAX
            return 0xf4;
    }
}

// callback for OUT instruction (X86).
static void hook_out(uc_engine *uc, uint32_t port, int size, uint32_t value, void *user_data)
{
    uint32_t tmp = 0;
    uint32_t eip;

    uc_reg_read(uc, UC_X86_REG_EIP, &eip);

    printf("--- writing to port 0x%x, size: %u, value: 0x%x, address: 0x%x\n", port, size, value, eip);

    // confirm that value is indeed the value of AL/AX/EAX
    switch(size) {
        default:
            return;   // should never reach this
        case 1:
            uc_reg_read(uc, UC_X86_REG_AL, &tmp);
            break;
        case 2:
            uc_reg_read(uc, UC_X86_REG_AX, &tmp);
            break;
        case 4:
            uc_reg_read(uc, UC_X86_REG_EAX, &tmp);
            break;
    }

//    printf("--- register value = 0x%x\n", tmp);
}

uc_engine* uc;

int main(int argc, char** argv)
{
    uc_hook trace;
    uc_err err;
    char *fname;
    FILE *f;
    uint8_t fcontent[1024 * 1024];    // 64KB for .COM file
    long fsize;

    if (argc == 1)
    {
        usage(argv[0]);
        return -1;
    }

    fname = argv[1];
    f = fopen(fname, "r");
    if (f == NULL)
    {
        printf("ERROR: failed to open file '%s'\n", fname);
        return -2;
    }

    // find the file size
    fseek(f, 0, SEEK_END); // seek to end of file
    fsize = ftell(f); // get current file pointer
    fseek(f, 0, SEEK_SET); // seek back to beginning of file

    // copy data in from 0x100
    memset(fcontent, 0, sizeof(fcontent));
    fread(fcontent + DOS_ADDR, fsize, 1, f);

    typedef struct {
      char signature[2]; /* == 0x5a4D */
      unsigned short bytes_in_last_block;
      unsigned short blocks_in_file;
      unsigned short num_relocs;
      unsigned short header_paragraphs;
      unsigned short min_extra_paragraphs;
      unsigned short max_extra_paragraphs;
      unsigned short ss;
      unsigned short sp;
      unsigned short checksum;
      unsigned short ip;
      unsigned short cs;
      unsigned short reloc_table_offset;
      unsigned short overlay_number;
    } EXE;

    typedef struct {
      unsigned short offset;
      unsigned short segment;
    } EXE_RELOC;


       


    err = uc_open (UC_ARCH_X86, UC_MODE_16, &uc);
    if (err) {
        fprintf (stderr, "Cannot initialize unicorn\n");
        return 1;
    }

    EXE* exe = (EXE*)&fcontent[DOS_ADDR];
    assert(exe->signature[0] == 'M');
    assert(exe->signature[1] == 'Z');
    unsigned int exe_data_start = exe->header_paragraphs * 16L;
    unsigned int relocoff = DOS_ADDR / 0x10 + exe->header_paragraphs;
    uint16_t t = exe->cs + relocoff;
    uc_reg_write(uc, UC_X86_REG_CS, &t);
    uint16_t ip = exe->ip;
    t = exe->ss + relocoff;
    uc_reg_write(uc, UC_X86_REG_SS, &t);
    uc_reg_write(uc, UC_X86_REG_SP, &exe->sp);

    printf("EXE start at 0x%04X:%04X (0x%04X:%04X)\n", exe->cs, exe->ip, exe->ss, exe->sp);

    EXE_RELOC* relocs = (EXE_RELOC*)((uint8_t*)exe + exe->reloc_table_offset);
    for(int i = 0; i < exe->num_relocs; i++) {
      EXE_RELOC* reloc = &relocs[i];
      uint16_t* v = (uint16_t*)&fcontent[relocoff * 16 + reloc->segment * 16 + reloc->offset];
      printf("reloc: offset %X segment %X [0x%04X old]\n", reloc->offset, reloc->segment, *v);
      *v += relocoff;
      printf("reloc: offset %X segment %X [0x%04X new]\n", reloc->offset, reloc->segment, *v);
    }


#if 1
// Some horrible patches to get around borland runtime

// Specifically for "MTKFLASH by Joseph Lin, MTK 1998 (Ver 1.83c)"

// Compare https://github.com/id-Software/wolf3d/blob/master/WOLFSRC/C0.ASM

fcontent[0x182d1] = 0x90;
fcontent[0x182d2] = 0x90;
fcontent[0x182d3] = 0x90;

fcontent[0x1007b+0] = 0x90;
fcontent[0x1007b+1] = 0x90;
fcontent[0x1007b+2] = 0x90;
#endif

    // map 64KB in
    if (uc_mem_map(uc, 0, 0xF0000, UC_PROT_ALL) || uc_mem_map(uc, 0xF0000, 0x10000, UC_PROT_READ))
    {
        printf("Failed to write emulation code to memory, quit!\n");
        uc_close(uc);
        return 0;
    }

    // initialize internal settings
    global_init();

    int10_init();
    int15_init();
    int21_init();

    // setup PSP
    psp_setup(0, fcontent, argc, argv);

    // write machine code to be emulated in, including the prefix PSP
    uc_mem_write(uc, 0, fcontent, DOS_ADDR + fsize);

    // handle interrupt ourself
    uc_hook_add(uc, &trace, UC_HOOK_INTR, hook_intr, NULL, 1, 0);

    uc_hook trace2;
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 1, 0);

    // uc IN instruction
    uc_hook trace3;
    uc_hook_add(uc, &trace3, UC_HOOK_INSN, hook_in, NULL, 1, 0, UC_X86_INS_IN);
    // uc OUT instruction
    uc_hook trace4;
    uc_hook_add(uc, &trace4, UC_HOOK_INSN, hook_out, NULL, 1, 0, UC_X86_INS_OUT);

    err = uc_emu_start(uc, ip, 0, 0, 0);
    if (err)
    {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
               err, uc_strerror(err));
    }

    uc_close(uc);

    return 0;
}
