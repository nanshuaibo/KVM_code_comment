#include "qemu/osdep.h"
#include "qemu-common.h"
#include "ui/console.h"

#include "cursor_hidden.xpm"
#include "cursor_left_ptr.xpm"

/* for creating built-in cursors */
static QEMUCursor *cursor_parse_xpm(const char *xpm[])
{
    QEMUCursor *c;
    uint32_t ctab[128];
    unsigned int width, height, colors, chars;
    unsigned int line = 0, i, r, g, b, x, y, pixel;
    char name[16];
    uint8_t idx;

    /* parse header line: width, height, #colors, #chars */
    if (sscanf(xpm[line], "%u %u %u %u",
               &width, &height, &colors, &chars) != 4) {
        fprintf(stderr, "%s: header parse error: \"%s\"\n",
                __FUNCTION__, xpm[line]);
        return NULL;
    }
    if (chars != 1) {
        fprintf(stderr, "%s: chars != 1 not supported\n", __FUNCTION__);
        return NULL;
    }
    line++;

    /* parse color table */
    for (i = 0; i < colors; i++, line++) {
        if (sscanf(xpm[line], "%c c %15s", &idx, name) == 2) {
            if (sscanf(name, "#%02x%02x%02x", &r, &g, &b) == 3) {
                ctab[idx] = (0xff << 24) | (b << 16) | (g << 8) | r;
                continue;
            }
            if (strcmp(name, "None") == 0) {
                ctab[idx] = 0x00000000;
                continue;
            }
        }
        fprintf(stderr, "%s: color parse error: \"%s\"\n",
                __FUNCTION__, xpm[line]);
        return NULL;
    }

    /* parse pixel data */
    c = cursor_alloc(width, height);
    for (pixel = 0, y = 0; y < height; y++, line++) {
        for (x = 0; x < height; x++, pixel++) {
            idx = xpm[line][x];
            c->data[pixel] = ctab[idx];
        }
    }
    return c;
}

/* nice for debugging */
void cursor_print_ascii_art(QEMUCursor *c, const char *prefix)
{
    uint32_t *data = c->data;
    int x,y;

    for (y = 0; y < c->height; y++) {
        fprintf(stderr, "%s: %2d: |", prefix, y);
        for (x = 0; x < c->width; x++, data++) {
            if ((*data & 0xff000000) != 0xff000000) {
                fprintf(stderr, " "); /* transparent */
            } else if ((*data & 0x00ffffff) == 0x00ffffff) {
                fprintf(stderr, "."); /* white */
            } else if ((*data & 0x00ffffff) == 0x00000000) {
                fprintf(stderr, "X"); /* black */
            } else {
                fprintf(stderr, "o"); /* other */
            }
        }
        fprintf(stderr, "|\n");
    }
}

QEMUCursor *cursor_builtin_hidden(void)
{
    return cursor_parse_xpm(cursor_hidden_xpm);
}

QEMUCursor *cursor_builtin_left_ptr(void)
{
    return cursor_parse_xpm(cursor_left_ptr_xpm);
}

QEMUCursor *cursor_alloc(int width, int height)
{
    QEMUCursor *c;
    int datasize = width * height * sizeof(uint32_t);

    c = g_malloc0(sizeof(QEMUCursor) + datasize);
    c->width  = width;
    c->height = height;
    c->refcount = 1;
    return c;
}

void cursor_get(QEMUCursor *c)
{
    c->refcount++;
}

void cursor_put(QEMUCursor *c)
{
    if (c == NULL)
        return;
    c->refcount--;
    if (c->refcount)
        return;
    g_free(c);
}

int cursor_get_mono_bpl(QEMUCursor *c)
{
    return (c->width + 7) / 8;
}

void cursor_set_mono(QEMUCursor *c,
                     uint32_t foreground, uint32_t background, uint8_t *image,
                     int transparent, uint8_t *mask)
{
    uint32_t *data = c->data;
    uint8_t bit;
    int x,y,bpl;

    bpl = cursor_get_mono_bpl(c);
    for (y = 0; y < c->height; y++) {
        bit = 0x80;
        for (x = 0; x < c->width; x++, data++) {
            if (transparent && mask[x/8] & bit) {
                *data = 0x00000000;
            } else if (!transparent && !(mask[x/8] & bit)) {
                *data = 0x00000000;
            } else if (image[x/8] & bit) {
                *data = 0xff000000 | foreground;
            } else {
                *data = 0xff000000 | background;
            }
            bit >>= 1;
            if (bit == 0) {
                bit = 0x80;
            }
        }
        mask  += bpl;
        image += bpl;
    }
}

void cursor_get_mono_image(QEMUCursor *c, int foreground, uint8_t *image)
{
    uint32_t *data = c->data;
    uint8_t bit;
    int x,y,bpl;

    bpl = cursor_get_mono_bpl(c);
    memset(image, 0, bpl * c->height);
    for (y = 0; y < c->height; y++) {
        bit = 0x80;
        for (x = 0; x < c->width; x++, data++) {
            if (((*data & 0xff000000) == 0xff000000) &&
                ((*data & 0x00ffffff) == foreground)) {
                image[x/8] |= bit;
            }
            bit >>= 1;
            if (bit == 0) {
                bit = 0x80;
            }
        }
        image += bpl;
    }
}

void cursor_get_mono_mask(QEMUCursor *c, int transparent, uint8_t *mask)
{
    uint32_t *data = c->data;
    uint8_t bit;
    int x,y,bpl;

    bpl = cursor_get_mono_bpl(c);
    memset(mask, 0, bpl * c->height);
    for (y = 0; y < c->height; y++) {
        bit = 0x80;
        for (x = 0; x < c->width; x++, data++) {
            if ((*data & 0xff000000) != 0xff000000) {
                if (transparent != 0) {
                    mask[x/8] |= bit;
                }
            } else {
                if (transparent == 0) {
                    mask[x/8] |= bit;
                }
            }
            bit >>= 1;
            if (bit == 0) {
                bit = 0x80;
            }
        }
        mask += bpl;
    }
}
