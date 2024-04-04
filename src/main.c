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
        return -1;
    }

    result = stat(name, &stat_buf);

    free(name);

    if (result) {
        if (errno == ENOENT) {
            return 0;
        } else {
            return -1;
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

    if (exists("bbfs", rec, &size) > 0) {
        type = ROMTYPE_REC;
        goto __get_type__exit;
    }

    if (exists("bbfs", app, &size) > 0) {
        type = ROMTYPE_APP;
        goto __get_type__exit;
    }

    if (exists("bbfs", aes, &size) > 0) {
        type = ROMTYPE_AES;
        goto __get_type__exit;
    }

    if (exists("bbfs", z64, &size) > 0) {
        type = ROMTYPE_Z64;
        goto __get_type__exit;
    }

__get_type__exit:
    free(z64);
    free(aes);
    free(app);
    free(rec);

    return type;
}

// clang-format off
#define ERROR(msg, ...) { console_clear(); printf(msg __VA_OPT__(,) __VA_ARGS__); console_render(); }
#define PANIC(msg, ...) { ERROR(msg __VA_OPT__(,) __VA_ARGS__); while (1); }
// clang-format on

typedef struct {
    uint32_t cid;
    ROMType type;
    Ticket *tikp;
} Launchable;

void setup_boot_params(void *data) {

    *(volatile uint32_t *)0x80000300 = *(uint32_t *)(data + 0x30);
    *(volatile uint32_t *)0x80000308 = *(uint32_t *)(data + 0x2C);
    *(volatile uint32_t *)0x80000318 = *(uint32_t *)(data + 0x34);

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

void launch(Launchable *rom) {
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
    if (filename == NULL) {
        ERROR("Failed to retrieve filename for application\n");
        return;
    }

    if (rom->type == ROMTYPE_AES) {
        rom->tikp->cmd.head.flags &= ~2;
    }

    status = exists("bbfs", "recrypt.sys", &recrypt_size);
    if (status < 0) {
        ERROR("Error checking whether recrypt.sys exists: %d\n", errno);
        free(filename);
        return;
    }

    if (status == 0) {
        ERROR("recrypt.sys does not exist\n");
        free(filename);
        return;
    }

    recrypt_buf = malloc(sizeof(uint8_t) * recrypt_size);
    if (recrypt_buf == NULL) {
        ERROR("Failed to allocate memory for recrypt.sys\n");
        free(filename);
        return;
    }

    recrypt_file = fopen("bbfs:/recrypt.sys", "r");
    if (recrypt_file == NULL) {
        ERROR("Failed to open recrypt.sys: %d\n", errno);
        free(filename);
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

    setup_boot_params(rom->tikp->cmd.desc);

    data_cache_writeback_invalidate_all();
    inst_cache_invalidate_all();

    disable_interrupts();

    skc_launch(entrypoint);

__launch_err:
    free(filename);
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
                    for (unsigned int i = 0; i < num_roms; i++) {
                        char *name = name_from_cid_type(roms[i].cid, roms[i].type);
                        printf("%c %s\n", (i == cursor_pos) ? '>' : ' ', name);
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
                        launch(&roms[cursor_pos]);
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
            roms[rom_index++] = (Launchable){.cid = cid, .type = type, .tikp = &tickets[i]};
        }
    }

    list_games(roms, rom_index);

    while (1)
        ;
}