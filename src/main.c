#include <libdragon.h>
#include <stdint.h>
#include <stdio.h>

volatile uint32_t *MI_HW_INTR_MASK = ((volatile uint32_t *)0xA430003C);

volatile uint8_t *STASH = ((volatile uint8_t *)0xA4A80100);

int main(void) {
    uint8_t usb_buf[0x100] __attribute__((aligned(4))) = {0};
    uint32_t *words = (void *)usb_buf;

    *MI_HW_INTR_MASK = (1 << 25) | (1 << 27);

    console_init();

    console_set_render_mode(RENDER_MANUAL);

    for (unsigned int i = 0; i < 0x100; i++) {
        usb_buf[i] = STASH[i];
    }

    while (1) {
        uint32_t index = 0;
        console_clear();

        printf("Hello from libdragon in SA2 context!\n");

        printf("USB:\n%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5],
               words[index + 6], words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;
        printf("%08lX%08lX%08lX%08lX%08lX%08lX%08lX%08lX", words[index], words[index + 1], words[index + 2], words[index + 3], words[index + 4], words[index + 5], words[index + 6],
               words[index + 7]);
        index += 8;

        console_render();
    }
}