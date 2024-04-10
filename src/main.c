#define _GNU_SOURCE

#include <libdragon.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

// clang-format off
#define ERROR(msg, ...) { printf(msg __VA_OPT__(,) __VA_ARGS__); console_render(); }
#define PANIC(msg, ...) { console_clear(); ERROR(msg __VA_OPT__(,) __VA_ARGS__); while (1); }
// clang-format on

volatile uint32_t *MI_HW_INTR_MASK = ((volatile uint32_t *)0xA430003C);

typedef struct {
    uint32_t pad;
    uint32_t ca_crl_ver;
    uint32_t cp_crl_ver;
    uint32_t size;
    uint32_t desc_flags;
    uint32_t key_iv[4];
    uint32_t hash[5];
    uint32_t iv[4];
    uint32_t flags;
    uint32_t rights;
    uint32_t skc_rights;
    uint32_t bbid;
    char issuer[64];
    uint32_t cid;
    uint32_t key[4];
    uint8_t sign[0x100];
} CMDHead;

typedef struct {
    uint8_t desc[0x2800];
    CMDHead head;
} CMD;

typedef struct {
    uint32_t bbid;
    uint16_t tid;
    uint16_t code;
    uint16_t limit;
    uint16_t pad;
    uint32_t ts_crl_ver;
    uint32_t cmd_iv[4];
    uint8_t ecc_pubkey[0x40];
    char issuer[64];
    uint8_t sign[0x100];
} TicketHead;

typedef struct {
    CMD cmd;
    TicketHead head;
} Ticket;

Ticket ticket = {.cmd = {.desc = {0},
                         .head =
                             {
                                 .pad = 0,
                                 .ca_crl_ver = 0,
                                 .cp_crl_ver = 0,
                                 .size = 0,
                                 .desc_flags = 0,
                                 .key_iv = {0},
                                 .hash = {0},
                                 .iv = {0},
                                 .flags = 0,
                                 .rights = 0xFFFFFFFF,
                                 .skc_rights = 0xFFFFFFFF,
                                 .bbid = 0,
                                 .issuer = {0},
                                 .cid = 0,
                                 .key = {0x27DAE074, 0x05A192C6, 0x3610BA22, 0x46EACF5C},
                                 .sign = {0},
                             }},
                 .head = {
                     .bbid = 0,
                     .tid = 0,
                     .code = 0,
                     .limit = 0,
                     .pad = 0,
                     .ts_crl_ver = 0,
                     .cmd_iv = {0},
                     .ecc_pubkey = {0},
                     .issuer = {0},
                     .sign = {0},
                 }};

bb_ticket_bundle_t bundle = {
    .ticket = &ticket,
    .ticket_certs = {NULL, NULL, NULL, NULL, NULL},
    .ticket_cmd = {NULL, NULL, NULL, NULL, NULL},
};

typedef struct {
    uint32_t type;
    char filename[8 + 1 + 3 + 1]; // 8.3 + null terminator
} direntry_t;

typedef enum {
    READDIR_SUCCESS = 0,
    READDIR_NOMEM,
    READDIR_LISTFAILED,
} ReadDirStatus;

ReadDirStatus read_dir(const char *const dir, direntry_t **out, unsigned int *count) {
    dir_t buf;
    int status;

    *count = 0;
    *out = malloc(1);
    if (*out == NULL) {
        return READDIR_NOMEM;
    }

    status = dir_findfirst(dir, &buf);
    if (status != 0) {
        free(*out);
        return READDIR_LISTFAILED;
    }

    while (status == 0) {
        direntry_t *temp = realloc(*out, sizeof(direntry_t) * (*count + 1));
        if (temp == NULL) {
            free(*out);
            return READDIR_NOMEM;
        }

        *out = temp;

        (*out)[*count].type = buf.d_type;
        strncpy((*out)[*count].filename, buf.d_name, 8 + 1 + 3 + 1);

        (*count)++;

        status = dir_findnext(dir, &buf);
    }

    return READDIR_SUCCESS;
}

int exists(const char *const drive, const char *const filename, off_t *out) {
    struct stat stat_buf;
    char *name;
    int result;
    if (asprintf(&name, "%s:/%s", drive, filename) < 0) {
        ERROR("Failed to determine drive filename\n");
        return -1;
    }

    result = stat(name, &stat_buf);

    free(name);

    if (result) {
        result = errno;
        if ((result == ENOENT) || (result == EBADF) || (result == EINVAL)) {
            return 0;
        } else {
            return -result;
        }
    } else {
        *out = stat_buf.st_size;
        return 1;
    }
}

char *name_from_cid(uint32_t cid, const char *const ext) {
    char *name;
    char ext_buf[4];

    memcpy(ext_buf, ext, 3);
    ext_buf[3] = 0;

    if (asprintf(&name, "%08lx.%-3s", cid, ext_buf) < 0) {
        return NULL;
    }

    return name;
}

typedef enum {
    ROMTYPE_REC,
    ROMTYPE_APP,
    ROMTYPE_AES,
    ROMTYPE_Z64,

    ROMTYPE_CHT,
    ROMTYPE_NONE,
} ROMType;

char *name_from_cid_type(uint32_t cid, ROMType type) {
    char *ext;

    switch (type) {
        case ROMTYPE_REC:
            {
                ext = "rec";
                break;
            }

        case ROMTYPE_APP:
            {
                ext = "app";
                break;
            }

        case ROMTYPE_AES:
            {
                ext = "aes";
                break;
            }

        case ROMTYPE_Z64:
            {
                ext = "z64";
                break;
            }

        case ROMTYPE_CHT:
            {
                ext = "cht";
                break;
            }

        default:
            {
                return NULL;
            }
    }

    return name_from_cid(cid, ext);
}

ROMType get_type(uint32_t cid) {
    ROMType type = ROMTYPE_NONE;
    off_t size;

    char *rec = name_from_cid_type(cid, ROMTYPE_REC);
    char *app = name_from_cid_type(cid, ROMTYPE_APP);
    char *aes = name_from_cid_type(cid, ROMTYPE_AES);
    char *z64 = name_from_cid_type(cid, ROMTYPE_Z64);

    if ((rec == NULL) || (app == NULL) || (aes == NULL) || (z64 == NULL)) {
        goto __get_type__exit;
    }

    if (exists("bbfs", z64, &size) > 0) {
        type = ROMTYPE_Z64;
        goto __get_type__exit;
    }

    if (exists("bbfs", aes, &size) > 0) {
        type = ROMTYPE_AES;
        goto __get_type__exit;
    }

    if (exists("bbfs", app, &size) > 0) {
        type = ROMTYPE_APP;
        goto __get_type__exit;
    }

    if (exists("bbfs", rec, &size) > 0) {
        type = ROMTYPE_REC;
        goto __get_type__exit;
    }

__get_type__exit:
    free(z64);
    free(aes);
    free(app);
    free(rec);

    return type;
}

typedef struct {
    uint32_t cid;
    ROMType type;
    Ticket *tikp;
    bool has_cht;
} Launchable;

void setup_boot_params(void *data, bool use_cheats) {
    *(volatile uint32_t *)0x80000300 = *(uint32_t *)(data + 0x30);
    //*(volatile uint32_t *)0x80000304 = 0;
    *(volatile uint32_t *)0x80000308 = *(uint32_t *)(data + 0x2C);
    /**(volatile uint32_t *)0x8000030C = 0;
     *(volatile uint32_t *)0x80000310 = 6102;
     *(volatile uint32_t *)0x80000314 = 0;*/
    *(volatile uint32_t *)0x80000318 = use_cheats ? 4 * 1024 * 1024 : *(uint32_t *)(data + 0x34);

    *(volatile uint32_t *)0x8000035C = *(uint32_t *)(data + 0x00);
    *(volatile uint32_t *)0x80000360 = *(uint32_t *)(data + 0x04);
    *(volatile uint32_t *)0x80000364 = *(uint32_t *)(data + 0x08);
    *(volatile uint32_t *)0x80000368 = *(uint32_t *)(data + 0x0C);
    *(volatile uint32_t *)0x8000036C = *(uint32_t *)(data + 0x10);
    *(volatile uint32_t *)0x80000370 = *(uint32_t *)(data + 0x14);
    *(volatile uint32_t *)0x80000374 = *(uint32_t *)(data + 0x18);
    *(volatile uint32_t *)0x80000378 = *(uint32_t *)(data + 0x1C);
    *(volatile uint32_t *)0x8000037C = *(uint32_t *)(data + 0x20);
    *(volatile uint32_t *)0x80000380 = *(uint32_t *)(data + 0x24);
    *(volatile uint32_t *)0x80000384 = *(uint32_t *)(data + 0x28);
}

#define REDIR_INTR_ENTRY (0x80000120)
#define REDIR_INTR_ENTRY_CACHED (REDIR_INTR_ENTRY | 0x20000000)

#define INTR_ENTRY (0x80000180)
#define WATCH_ENTRY (0x80000190)

// #define CODE_HANDLER (0x80000204)
//  #define CODE_HANDLER_END (0x800002E0)
// #define CODE_HANDLER_END (0x800002A0)

#define CODE_HANDLER (0x80500000)
#define CODE_HANDLER_END (0x80600000)

// #define INTR_HANDLER (0x800002C0)
#define INTR_HANDLER (0x80000204)
#define WATCH_HANDLER (0x807FF000)

#define MI_INTR ((uint32_t)MI_INTERRUPT)

void setup_cheats(void) {
    const uint32_t intr_entry[] = {
        0x3C1A0000 | ((INTR_HANDLER >> 16) & 0xFFFF), // lui $k0, %HI(INTR_HANDLER)
        0x375A0000 | (INTR_HANDLER & 0xFFFF),         // ori $k0, $k0, %LO(INTR_HANDLER)
        0x03400008,                                   // jr  $k0
        0x00000000,                                   //  nop
    };

    memcpy((void *)INTR_ENTRY, intr_entry, sizeof(intr_entry));

    const uint32_t watch_entry[] = {
        0x3C1A0000 | ((WATCH_HANDLER >> 16) & 0xFFFF), // lui $k0, %HI(WATCH_HANDLER)
        0x375A0000 | (WATCH_HANDLER & 0xFFFF),         // ori $k0, $k0, %LO(WATCH_HANDLER)
        0x03400008,                                    // jr  $k0
        0x00000000,                                    //  nop
    };

    memcpy((void *)WATCH_ENTRY, watch_entry, sizeof(watch_entry));

    const uint32_t intr_handler[] = {
        0x401A6800,                                        //  mfc0  $k0, Cause
        0x335A007C,                                        //  andi  $k0, $k0,   0x007C
        0x341B0000 | (EXCEPTION_CODE_FLOATING_POINT << 2), //  ori   $k1, $zero, (EXCEPTION_CODE_FLOATING_POINT << 2)
        0x135B000E,                                        //  beq   $k0, $k1,   3f
        0x00000000,                                        //   nop
        0x341B0000 | (EXCEPTION_CODE_WATCH << 2),          //  ori   $k1, $zero, (EXCEPTION_CODE_WATCH << 2)
        0x135B0009,                                        //  beq   $k0, $k1,   2f
        0x00000000,                                        //   nop
        0x17400005,                                        //  bnez  $k0,        1f
        0x3C1A0000 | ((MI_INTR >> 16) & 0xFFFF),           //   lui  $k0, %HI(MI_INTERRUPT)
        0x8F5A0000 | (MI_INTR & 0xFFFF),                   //  lw    $k0, %LO(MI_INTERRUPT)($k0)
        0x335B0000 | (MI_INTERRUPT_SI),                    //  andi  $k1, $k0,   MI_INTERRUPT_SI
        0x17600001,                                        //  bnez  $k1,        1f
        0x00000000,                                        //   nop
                                                           // 1:
        0x08000000 | ((CODE_HANDLER & 0x0FFFFFFF) >> 2),   //  j CODE_HANDLER
        0x00000000,                                        //   nop
                                                           // 2:
        0x08000000 | ((WATCH_ENTRY & 0x0FFFFFFF) >> 2),    //  j WATCH_ENTRY
        0x00000000,                                        //   nop
                                                           // 3:
        0x445AF800,                                        //  cfc1  $k0, FCR31
        0x3C1BFFFC,                                        //  lui   $k1, 0xFFFC
        0x377B0FFF,                                        //  ori   $k1, $k1,   0x0FFF
        0x035BD024,                                        //  and   $k0, $k0,   $k1
        0x44DAF800,                                        //  ctc1  $k0, FCR31
        0x00000000,                                        //   nop
        0x401A7000,                                        //  mfc0  $k0, EPC
        0x00000000,                                        //   nop
        0x275A0004,                                        //  addiu $k0, $k0,   4
        0x409A7000,                                        //  mtc0  $k0, EPC
        0x00000000,                                        //   nop
        0x401AF000,                                        //  mfc0  $k0, ErrorEPC
        0x00000000,                                        //   nop
        0x275A0004,                                        //  addiu $k0, $k0,   4
        0x409AF000,                                        //  mtc0  $k0, ErrorEPC
        0x00000000,                                        //   nop
        0x42000018,                                        //  eret
        0x00000000,                                        //   nop
    };

    /*const uint32_t intr_handler[] = {
        0x401A6800,                                          //  mfc $k0, Cause
        0x341B0000 | (EXCEPTION_CODE_WATCH << 2),            //  ori  $k1, $zero, (EXCEPTION_CODE_WATCH << 2)
        0x335A007C,                                          //  andi $k0, $k0,   0x7C
        0x135B000C,                                          //  beq  $k0, $k1,   3f
        0x00000000,                                          //   nop
        0x17400007,                                          //  bnez $k0,        1f
        0x00000000,                                          //   nop
        0x3C1A0000 | ((MI_INTR >> 16) & 0xFFFF),             //  lui  $k0, %HI(MI_INTERRUPT)
        0x8F5A0000 | (MI_INTR & 0xFFFF),                     //  lw   $k0, %LO(MI_INTERRUPT)($k0)
        0x00000000,                                          //   nop
        0x335B0000 | (MI_INTERRUPT_SI),                      //  andi $k1, $k0,   MI_INTERRUPT_SI
        0x17600003,                                          //  bnez $k1,        2f
        0x00000000,                                          //   nop
                                                             // 1:
        0x08000000 | ((REDIR_INTR_ENTRY & 0x0FFFFFFF) >> 2), //  j REDIR_INTR_ENTRY
        0x00000000,                                          //   nop
                                                             // 2:
        0x08000000 | ((CODE_HANDLER & 0x0FFFFFFF) >> 2),     //  j CODE_HANDLER
                                                             // --- missing nop ---
                                                             // 3:
        0x3C1A0000 | ((WATCH_HANDLER >> 16) & 0xFFFF),       //  lui  $k0, %HI(WATCH_HANDLER)
        0x375A0000 | (WATCH_HANDLER & 0xFFFF),               //  ori  $k0, $k0, %LO(WATCH_HANDLER)
        0x03400008,                                          //  jr $k0
        0x00000000,                                          //   nop
    };*/

    memcpy((void *)UncachedAddr(INTR_HANDLER), intr_handler, sizeof(intr_handler));

    const uint32_t watch_handler[] = {
        0x27BDFF90,                                              //  addiu $sp, $sp, -112
        0xAFA20068,                                              //  sw    $v0, 0x68($sp)
        0xAFA3006C,                                              //  sw    $v1, 0x6C($sp)
        0xAFA80010,                                              //  sw    $t0, 0x10($sp)
        0xAFA90014,                                              //  sw    $t1, 0x14($sp)
        0xAFAA0018,                                              //  sw    $t2, 0x18($sp)
        0xAFAB001C,                                              //  sw    $t3, 0x1C($sp)
        0xAFAC0020,                                              //  sw    $t4, 0x20($sp)
        0xAFAD0024,                                              //  sw    $t5, 0x24($sp)
        0xAFAE0028,                                              //  sw    $t6, 0x28($sp)
        0xAFAF002C,                                              //  sw    $t7, 0x2C($sp)
        0xAFB80030,                                              //  sw    $t8, 0x30($sp)
        0xAFB90034,                                              //  sw    $t9, 0x34($sp)
        0xAFA40038,                                              //  sw    $a0, 0x38($sp)
        0xAFA5003C,                                              //  sw    $a1, 0x3C($sp)
        0xAFA60040,                                              //  sw    $a2, 0x40($sp)
        0xAFA70044,                                              //  sw    $a3, 0x44($sp)
        0xAFB00048,                                              //  sw    $s0, 0x48($sp)
        0xAFB1004C,                                              //  sw    $s1, 0x4C($sp)
        0xAFB20050,                                              //  sw    $s2, 0x50($sp)
        0xAFB30054,                                              //  sw    $s3, 0x54($sp)
        0xAFB40058,                                              //  sw    $s4, 0x58($sp)
        0xAFB5005C,                                              //  sw    $s5, 0x5C($sp)
        0xAFB60060,                                              //  sw    $s6, 0x60($sp)
        0xAFB70064,                                              //  sw    $s7, 0x64($sp)
        0x03A04021,                                              //  move  $t0, $sp
        0x25090070,                                              //  addiu $t1, $t0, 112
        0x3C0A0000 | ((INTR_ENTRY >> 16) & 0xFFFF),              //  lui   $t2, %HI(INTR_ENTRY)
        0x354A0000 | (INTR_ENTRY & 0xFFFF),                      //  ori   $t2, $t2, %LO(INTR_ENTRY)
                                                                 // 1:
        0x8D0B0010,                                              //  lw    $t3, 0x10($t0)
        0x00000000,                                              //  nop
        0x114B0006,                                              //  beq   $t2, $t3, 1f
        0x00000000,                                              //   nop
        0x25080004,                                              //  addiu $t0, $t0, 4
        0x1509FFFA,                                              //  bne   $t0, $t1, 1b
        0x00000000,                                              //   nop
        0x04010004,                                              //  b               2f
        0x00000000,                                              //   nop
                                                                 // 1:
        0x3C0A0000 | ((REDIR_INTR_ENTRY_CACHED >> 16) & 0xFFFF), //  lui   $t2, %HI(REDIR_INTR_ENTRY_CACHED)
        0x354A0000 | (REDIR_INTR_ENTRY_CACHED & 0xFFFF),         //  ori   $t2, $t2, %LO(REDIR_INTR_ENTRY_CACHED)
        0xAD0A0010,                                              //  sw    $t2, 0x10($t0)
                                                                 // 2:
        0x8FA20068,                                              //  lw    $v0, 0x68($sp)
        0x8FA3006C,                                              //  lw    $v1, 0x6C($sp)
        0x8FA80010,                                              //  lw    $t0, 0x10($sp)
        0x8FA90014,                                              //  lw    $t1, 0x14($sp)
        0x8FAA0018,                                              //  lw    $t2, 0x18($sp)
        0x8FAB001C,                                              //  lw    $t3, 0x1C($sp)
        0x8FAC0020,                                              //  lw    $t4, 0x20($sp)
        0x8FAD0024,                                              //  lw    $t5, 0x24($sp)
        0x8FAE0028,                                              //  lw    $t6, 0x28($sp)
        0x8FAF002C,                                              //  lw    $t7, 0x2C($sp)
        0x8FB80030,                                              //  lw    $t8, 0x30($sp)
        0x8FB90034,                                              //  lw    $t9, 0x34($sp)
        0x8FA40038,                                              //  lw    $a0, 0x38($sp)
        0x8FA5003C,                                              //  lw    $a1, 0x3C($sp)
        0x8FA60040,                                              //  lw    $a2, 0x40($sp)
        0x8FA70044,                                              //  lw    $a3, 0x44($sp)
        0x8FB00048,                                              //  lw    $s0, 0x48($sp)
        0x8FB1004C,                                              //  lw    $s1, 0x4C($sp)
        0x8FB20050,                                              //  lw    $s2, 0x50($sp)
        0x8FB30054,                                              //  lw    $s3, 0x54($sp)
        0x8FB40058,                                              //  lw    $s4, 0x58($sp)
        0x8FB5005C,                                              //  lw    $s5, 0x5C($sp)
        0x8FB60060,                                              //  lw    $s6, 0x60($sp)
        0x8FB70064,                                              //  lw    $s7, 0x64($sp)
        0x27BD0070,                                              //  addiu $sp, $sp, 112
        0x42000018,                                              //  eret
        0x00000000,                                              //   nop
    };

    memcpy((void *)UncachedAddr(WATCH_HANDLER), watch_handler, sizeof(watch_handler));

    // set watchpoint on INTR_ENTRY write
    __asm__ volatile("mtc0 %0, $18\n" : : "r"((INTR_ENTRY & ~0x80000000) | ((1 << 0))));
    __asm__ volatile("mtc0 %0, $19\n" : : "r"((1 << 30)));
}

typedef struct {
    uint8_t type;
    uint32_t addr;
    uint16_t extra;
} Cheat;

uint32_t cheat_type(uint8_t *cheat_buf, size_t cheat) {
    const size_t index = cheat * 6;
    return (cheat_buf[index]);
}

uint32_t cheat_addr(uint8_t *cheat_buf, size_t cheat) {
    const size_t index = cheat * 6;
    return (cheat_buf[index + 1] << 16) | (cheat_buf[index + 2] << 8) | (cheat_buf[index + 3]);
}

uint32_t cheat_extra(uint8_t *cheat_buf, size_t cheat) {
    const size_t index = cheat * 6;
    return (cheat_buf[index + 4] << 8) | (cheat_buf[index + 5]);
}

void parse_codes(uint8_t *cheat_buf, off_t cheats_size) {
    const size_t num_cheats = cheats_size / 6;

    uint32_t *const code = UncachedAddr(CODE_HANDLER);
    size_t code_index = 0;
    size_t cheat = 0;

    // clang-format off
#define NEXT_CHEAT(ident) if (cheat >= num_cheats) {break;} Cheat ident = {.type = cheat_type(cheat_buf, cheat), .addr = cheat_addr(cheat_buf, cheat), .extra = cheat_extra(cheat_buf, cheat)}; cheat++
    // clang-format on

    while (((void *)&code[code_index] < UncachedAddr(CODE_HANDLER_END)) && (cheat < num_cheats)) {
        NEXT_CHEAT(cur);

        if ((cur.type == 0) && (cur.addr == 0) && (cur.extra == 0)) {
            break;
        }
        printf("cheat %02X%06lX %04X\n", cur.type, cur.addr, cur.extra);
        console_render();

        if ((cur.type & 0xF0) == 0xD0) {
            // 8-bit / 16-bit equal-to / not-equal-to

            code[code_index++] = 0x3C1A8000 | (cur.addr >> 16);                                              // lui   $k0, %HI(cur.addr) | 0x8000
            code[code_index++] = 0x375A0000 | (cur.addr & 0xFFFF);                                           // ori   $k0, $k0,   %LO(cur.addr)
            code[code_index++] = ((cur.type & (1 << 0)) & !(cur.addr & (1 << 0))) ? 0x875A0000 : 0x835A0000; // lh    $k0, 0($k0) : lb    $k0, 0($k0)
            code[code_index++] = 0x241B0000 | (cur.extra);                                                   // addiu $k1, $zero, cur.extra
            code[code_index++] = (cur.type & (1 << 1)) ? 0x135B0004 : 0x175B0004;                            // beq   $k0, $k1,   4 : bne   $k0, $k1,   4
        } else if ((cur.type & 0xF0) == 0x80) {
            // 8-bit / 16-bit cached store

            code[code_index++] = 0x3C1A8000 | (cur.addr >> 16);                                              // lui   $k0, %HI(cur.addr) | 0x8000
            code[code_index++] = 0x375A0000 | (cur.addr & 0xFFFF);                                           // ori   $k0, $k0,   %LO(cur.addr)
            code[code_index++] = 0x241B0000 | (cur.extra);                                                   // addiu $k1, $zero, cur.extra
            code[code_index++] = ((cur.type & (1 << 0)) & !(cur.addr & (1 << 0))) ? 0xA75B0000 : 0xA35B0000; // sh    $k1, 0($k0) : sb    $k1, 0($k0)
        } else if ((cur.type & 0xF0) == 0xA0) {
            // 8-bit / 16-bit uncached store

            code[code_index++] = 0x3C1AA000 | (cur.addr >> 16);                                              // lui   $k0, %HI(cur.addr) | 0xA000
            code[code_index++] = 0x375A0000 | (cur.addr & 0xFFFF);                                           // ori   $k0, $k0,   %LO(cur.addr)
            code[code_index++] = 0x241B0000 | (cur.extra);                                                   // addiu $k1, $zero, cur.extra
            code[code_index++] = ((cur.type & (1 << 0)) & !(cur.addr & (1 << 0))) ? 0xA75B0000 : 0xA35B0000; // sh    $k1, 0($k0) : sb    $k1, 0($k0)
        } else if ((cur.type & 0xF0) == 0xF0) {
            // 8-bit / 16-bit write on boot

            if ((cur.type & (1 << 0)) & !(cur.addr & (1 << 0))) {
                *(uint16_t *)UncachedAddr(KSEG0_START_ADDR + cur.addr) = cur.extra;
            } else {
                *(uint8_t *)UncachedAddr(KSEG0_START_ADDR + cur.addr) = cur.extra;
            }
        }
    }

    code[code_index++] = 0x3C1A0000 | ((REDIR_INTR_ENTRY >> 16) & 0xFFFF); // lui $k0, %HI(REDIR_INTR_ENTRY)
    code[code_index++] = 0x375A0000 | (REDIR_INTR_ENTRY & 0xFFFF);         // ori $k0, %LO(REDIR_INTR_ENTRY)
    code[code_index++] = 0x03400008;                                       // jr $k0
    code[code_index++] = 0x00000000;                                       //  nop
}

void launch(Launchable *rom, bool use_cheats) {
    int status;
    off_t recrypt_size;
    uint8_t *recrypt_buf;
    FILE *recrypt_file;
    bb_ticket_bundle_t bundle;
    int16_t *blocks;
    void *entrypoint;
    unsigned int load_offset;
    void *load_addr;
    char *filename = name_from_cid_type(rom->cid, rom->type);
    char *chtname = NULL;
    uint8_t *cheat_buf = NULL;
    FILE *cheat_file;
    off_t cheats_size = 0;

    if (filename == NULL) {
        ERROR("Failed to retrieve filename for application\n");
        return;
    }

    if (use_cheats) {
        struct stat cht_stat;
        char *device_filename;

        chtname = name_from_cid_type(rom->cid, ROMTYPE_CHT);
        if (chtname == NULL) {
            ERROR("Failed to load cheat filename for application\n");
            free(filename);
            return;
        }

        if (asprintf(&device_filename, "bbfs:/%s", chtname) < 0) {
            ERROR("Failed to determine cheat filename for application\n");
            free(filename);
            free(chtname);
            return;
        }

        free(chtname);

        if (stat(device_filename, &cht_stat)) {
            ERROR("Failed to stat cheat file\n");
            free(filename);
            free(device_filename);
            return;
        }

        cheats_size = cht_stat.st_size;

        cheat_buf = malloc(sizeof(uint8_t) * cheats_size);
        if (cheat_buf == NULL) {
            ERROR("Failed to allocate buffer for cheat file\n");
            free(filename);
            free(device_filename);
            return;
        }

        cheat_file = fopen(device_filename, "r");
        if (cheat_file == NULL) {
            ERROR("Failed to open cheat file\n");
            free(filename);
            free(device_filename);
            free(cheat_buf);
            return;
        }

        free(device_filename);

        if (fread(cheat_buf, sizeof(uint8_t), cheats_size, cheat_file) < 0) {
            ERROR("Failed to read cheat file\n");
            free(filename);
            free(cheat_buf);
            return;
        }

        fclose(cheat_file);
    }

    if (rom->type == ROMTYPE_AES) {
        rom->tikp->cmd.head.flags &= ~2;
    }

    status = exists("bbfs", "recrypt.sys", &recrypt_size);
    if (status < 0) {
        ERROR("Error checking whether recrypt.sys exists: %d\n", errno);
        free(filename);
        free(cheat_buf);
        return;
    }

    if (status == 0) {
        ERROR("recrypt.sys does not exist\n");
        free(filename);
        free(cheat_buf);
        return;
    }

    recrypt_buf = malloc(sizeof(uint8_t) * recrypt_size);
    if (recrypt_buf == NULL) {
        ERROR("Failed to allocate memory for recrypt.sys\n");
        free(filename);
        free(cheat_buf);
        return;
    }

    recrypt_file = fopen("bbfs:/recrypt.sys", "r");
    if (recrypt_file == NULL) {
        ERROR("Failed to open recrypt.sys: %d\n", errno);
        free(filename);
        free(cheat_buf);
        free(recrypt_buf);
        return;
    }

    if (fread(recrypt_buf, sizeof(uint8_t), recrypt_size, recrypt_file) < 0) {
        ERROR("Failed to read recrypt.sys\n");
        goto __launch_err;
    }

    bundle = (bb_ticket_bundle_t){
        .ticket = rom->tikp,
        .ticket_certs = {NULL, NULL, NULL, NULL, NULL},
        .ticket_cmd = {NULL, NULL, NULL, NULL, NULL},
    };

    if (skc_launch_setup(&bundle, NULL, recrypt_buf)) {
        ERROR("Failed to set up launch\n");
        goto __launch_err;
    }

    blocks = bbfs_get_file_blocks(filename);

    nand_mmap_begin();

    if (nand_mmap(0x10000000, blocks, NAND_MMAP_ENCRYPTED)) {
        ERROR("Failed to set up ATB\n");
        free(blocks);
        goto __launch_err;
    }

    nand_mmap_end();

    entrypoint = (void *)io_read(0x10000008);
    load_offset = (rom->tikp->cmd.head.flags & 2) ? 0 : 0x1000;
    load_addr = entrypoint - (0x1000 - load_offset);

    dma_read(load_addr, 0x10000000 + load_offset, MIN(rom->tikp->cmd.head.size - load_offset, 1024 * 1024 + (0x1000 - load_offset)));

    disable_interrupts();

    setup_boot_params(rom->tikp->cmd.desc, use_cheats);

    data_cache_writeback_invalidate_all();

    if (use_cheats) {
        setup_cheats();
        parse_codes(cheat_buf, cheats_size);
    }

    data_cache_writeback_invalidate_all();
    inst_cache_invalidate_all();

    skc_launch(entrypoint);

__launch_err:
    free(filename);
    free(cheat_buf);
    free(recrypt_buf);
    fclose(recrypt_file);
}

#define STICK_DIR_CUTOFF (64)

void list_games(Launchable *roms, unsigned int num_roms) {
    enum {
        PrintList,
        WaitInput,
    } menu_state = PrintList;
    unsigned int cursor_pos = 0;
    bool run = true;
    joypad_inputs_t inputs = {0}, prev_inputs;

    joypad_init();

    if (num_roms == 0) {
        PANIC("No launchable applications found\n");
    }

    while (run) {
        switch (menu_state) {
            case PrintList:
                {
                    console_clear();

                    printf("Press A to launch or Start to launch without cheats\n");

                    for (unsigned int i = 0; i < num_roms; i++) {
                        char *name = name_from_cid_type(roms[i].cid, roms[i].type);
                        printf("%c %s%s\n", (i == cursor_pos) ? '>' : ' ', name, roms[i].has_cht ? " (found cheats)" : "");
                        free(name);
                    }

                    console_render();

                    menu_state = WaitInput;

                    break;
                }

            case WaitInput:
                {
                    bool changed = false;

                    joypad_poll();

                    prev_inputs = inputs;
                    inputs = joypad_get_inputs(0);

                    if ((inputs.stick_y < -STICK_DIR_CUTOFF) && !(prev_inputs.stick_y < -STICK_DIR_CUTOFF) && (cursor_pos < (num_roms - 1))) {
                        cursor_pos += 1;
                        changed = true;
                    }

                    if ((inputs.stick_y > STICK_DIR_CUTOFF) && !(prev_inputs.stick_y > STICK_DIR_CUTOFF) && (cursor_pos > 0)) {
                        cursor_pos -= 1;
                        changed = true;
                    }

                    if ((inputs.btn.a) && !(prev_inputs.btn.a)) {
                        launch(&roms[cursor_pos], roms[cursor_pos].has_cht);
                    } else if ((inputs.btn.start) && !(prev_inputs.btn.start)) {
                        launch(&roms[cursor_pos], false);
                    }

                    if (changed) {
                        menu_state = PrintList;
                    }

                    break;
                }
        }
    }
}

int main(void) {
    off_t ticket_size;
    int status;
    FILE *ticket_file;
    uint8_t *ticket_buf;
    uint32_t num_tickets;
    Ticket *tickets;
    Launchable *roms;
    unsigned int rom_index;

    char fname_buf[100];

    *MI_HW_INTR_MASK = (1 << 25);

    console_init();

    console_set_render_mode(RENDER_MANUAL);

    if (bbfs_init()) {
        PANIC("Error initialising BBFS\n");
    }

    status = exists("bbfs", "ticket.sys", &ticket_size);
    if (status < 0) {
        PANIC("Error checking whether ticket.sys exists: %d\n", errno);
    }

    if (status == 0) {
        PANIC("ticket.sys does not exist\n");
    }

    ticket_buf = malloc(sizeof(uint8_t) * ticket_size);

    ticket_file = fopen("bbfs:/ticket.sys", "r");
    if (ticket_file == NULL) {
        PANIC("Failed to open ticket.sys: %d\n", errno);
    }

    if (fread(ticket_buf, sizeof(uint8_t), ticket_size, ticket_file) < 4) {
        PANIC("Failed to read ticket.sys\n");
    }

    num_tickets = *(uint32_t *)ticket_buf;
    tickets = (Ticket *)(ticket_buf + 4);

    roms = malloc(sizeof(Launchable) * num_tickets);
    rom_index = 0;

    for (uint32_t i = 0; i < num_tickets; i++) {
        uint32_t cid = tickets[i].cmd.head.cid;
        ROMType type = get_type(cid);

        if (type != ROMTYPE_NONE) {
            Launchable rom = (Launchable){.cid = cid, .type = type, .tikp = &tickets[i], .has_cht = false};

            char *cht = name_from_cid_type(cid, ROMTYPE_CHT);
            if (cht == NULL) {
                ERROR("Failed to determine name of cheat file\n");
            } else {
                off_t size;
                status = exists("bbfs", cht, &size);

                if (status < 0) {
                    ERROR("Failed to stat cheat file %s: %d\n", cht, -status);
                } else {
                    rom.has_cht = (status > 0);
                }

                free(cht);
            }

            roms[rom_index++] = rom;
        }
    }

    list_games(roms, rom_index);

    while (1)
        ;
}