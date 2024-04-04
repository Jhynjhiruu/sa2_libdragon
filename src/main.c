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

int main(void) {
    struct stat stat_buf;
    int16_t *blocks;
    void *entrypoint;
    void *load_addr;

    *MI_HW_INTR_MASK = (1 << 25);

    console_init();

    console_set_render_mode(RENDER_MANUAL);

    printf("Line %d\n", __LINE__);
    console_render();

    if (bbfs_init()) {
        console_clear();
        printf("Error initialising BBFS\n");
        console_render();
        while (1)
            ;
    }

    printf("Line %d\n", __LINE__);
    console_render();

    if (stat("bbfs:/00000001.app", &stat_buf)) {
        console_clear();
        printf("Error calling stat: %d\n", errno);
        console_render();
        while (1)
            ;
    }

    printf("Line %d\n", __LINE__);
    console_render();

    blocks = bbfs_get_file_blocks("00000001.app");
    if (blocks == NULL) {
        console_clear();
        printf("Error getting file blocks\n");
        console_render();
        while (1)
            ;
    }

    printf("Line %d\n", __LINE__);
    console_render();

    ticket.cmd.head.size = stat_buf.st_size;

    if (skc_launch_setup(&bundle, NULL, NULL)) {
        console_clear();
        printf("Error calling skLaunchSetup");
        console_render();
        while (1)
            ;
    }

    printf("Line %d\n", __LINE__);
    console_render();

    nand_mmap_begin();

    if (nand_mmap(0x10000000, blocks, NAND_MMAP_ENCRYPTED)) {
        console_clear();
        printf("Error mapping file blocks\n");
        console_render();
        while (1)
            ;
    }

    nand_mmap_end();

    printf("Line %d\n", __LINE__);
    console_render();

    wait_ms(500);

    entrypoint = (void *)io_read(0x10000008);
    load_addr = entrypoint - 0x1000;

    printf("Line %d\n", __LINE__);
    printf("Entrypoint: %p, base addr: %p\n", entrypoint, (void *)((*((volatile uint32_t *)0xA4610504) & 0xFFFF) << 14));
    console_render();

    wait_ms(1500);

    dma_read(load_addr, 0x10000000, MIN(stat_buf.st_size, 1024 * 1024 + 0x1000));

    printf("Line %d\n", __LINE__);
    console_render();

    data_cache_writeback_invalidate_all();
    inst_cache_invalidate_all();

    printf("Line %d\n", __LINE__);
    console_render();

    *(volatile uint32_t *)0x80000300 = 1;
    *(volatile uint32_t *)0x80000308 = 0xB0000000;
    *(volatile uint32_t *)0x80000318 = 8 * 1024 * 1024;

    printf("Entrypoint: %p\n", entrypoint);
    printf("%08lX %08lX %08lX %08lX\n", io_read(0x10000000), io_read(0x10000004), io_read(0x10000008), io_read(0x1000000C));
    console_render();

    wait_ms(1500);

    if (entrypoint != NULL) {
        printf("%08lX %08lX %08lX %08lX\n", *(uint32_t *)(entrypoint), *(uint32_t *)(entrypoint + 0x04), *(uint32_t *)(entrypoint + 0x08), *(uint32_t *)(entrypoint + 0x0C));
    }
    console_render();

    wait_ms(1500);

    skc_launch(entrypoint);
}