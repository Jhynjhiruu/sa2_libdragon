#include <libdragon.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/errno.h>
#include <sys/fcntl.h>
#include <sys/stat.h>
#include <sys/unistd.h>

#define MIN(a, b) (((a) < (b)) ? (b) : (a))

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
    size_t num = snprintf(NULL, 0, "%s:/%s", drive, filename) + 1;
    name = malloc(num);
    if (name == NULL) {
        return -1;
    }

    snprintf(name, num, "%s:/%s", drive, filename);

    if (stat(name, &stat_buf)) {
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
    char ext_buf[4];

    char *ret = malloc(8 + 1 + 3 + 1);
    if (ret == NULL) {
        return NULL;
    }

    memcpy(ext_buf, ext, 3);
    ext_buf[3] = 0;

    snprintf(ret, 8 + 1 + 3 + 1, "%08lx.%-3s", cid, ext_buf);

    return ret;
}

// clang-format off
#define PANIC(msg, ...) { console_clear(); printf(msg __VA_OPT__(,) __VA_ARGS__); console_render(); while (1); }
// clang-format on

int main(void) {
    off_t ticket_size;
    int status;
    FILE *ticket_file;
    uint8_t *ticket_buf;
    uint32_t num_tickets;
    Ticket *tickets;

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

    for (uint32_t i = 0; i < num_tickets; i++) {
        off_t size;

        char *rec = name_from_cid(tickets[i].cmd.head.cid, "rec");
        if (rec == NULL) {
            PANIC("Failed to format rec name\n");
        }

        if (exists("bbfs", rec, &size) > 0) {
            printf("%s\n", rec);
        } else {
            char *app = name_from_cid(tickets[i].cmd.head.cid, "app");
            if (app == NULL) {
                PANIC("Failed to format app name\n");
            }

            if (exists("bbfs", app, &size) > 0) {
                printf("%s\n", app);
            } else {
                char *aes = name_from_cid(tickets[i].cmd.head.cid, "aes");
                if (aes == NULL) {
                    PANIC("Failed to format aes name\n");
                }

                if (exists("bbfs", aes, &size) > 0) {
                    printf("%s\n", aes);
                }
                free(aes);
            }
            free(app);
        }
        free(rec);
    }
}