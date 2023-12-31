/*
 * QTest testcase for the M25P80 Flash (Using the Aspeed SPI
 * Controller)
 *
 * Copyright (C) 2016 IBM Corp.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "libqtest.h"

/*
 * ASPEED SPI Controller registers
 */
#define R_CONF              0x00
#define   CONF_ENABLE_W0       (1 << 16)
#define R_CE_CTRL           0x04
#define   CRTL_EXTENDED0       0  /* 32 bit addressing for SPI */
#define R_CTRL0             0x10
#define   CTRL_CE_STOP_ACTIVE  (1 << 2)
#define   CTRL_USERMODE        0x3

#define ASPEED_FMC_BASE    0x1E620000
#define ASPEED_FLASH_BASE  0x20000000

/*
 * Flash commands
 */
enum {
    JEDEC_READ = 0x9f,
    BULK_ERASE = 0xc7,
    READ = 0x03,
    PP = 0x02,
    WREN = 0x6,
    EN_4BYTE_ADDR = 0xB7,
    ERASE_SECTOR = 0xd8,
};

#define FLASH_JEDEC         0x20ba19  /* n25q256a */
#define FLASH_SIZE          (32 * 1024 * 1024)

#define PAGE_SIZE           256

/*
 * Use an explicit bswap for the values read/wrote to the flash region
 * as they are BE and the Aspeed CPU is LE.
 */
static inline uint32_t make_be32(uint32_t data)
{
    return bswap32(data);
}

static void spi_conf(uint32_t value)
{
    uint32_t conf = readl(ASPEED_FMC_BASE + R_CONF);

    conf |= value;
    writel(ASPEED_FMC_BASE + R_CONF, conf);
}

static void spi_ctrl_start_user(void)
{
    uint32_t ctrl = readl(ASPEED_FMC_BASE + R_CTRL0);

    ctrl |= CTRL_USERMODE | CTRL_CE_STOP_ACTIVE;
    writel(ASPEED_FMC_BASE + R_CTRL0, ctrl);

    ctrl &= ~CTRL_CE_STOP_ACTIVE;
    writel(ASPEED_FMC_BASE + R_CTRL0, ctrl);
}

static void spi_ctrl_stop_user(void)
{
    uint32_t ctrl = readl(ASPEED_FMC_BASE + R_CTRL0);

    ctrl |= CTRL_USERMODE | CTRL_CE_STOP_ACTIVE;
    writel(ASPEED_FMC_BASE + R_CTRL0, ctrl);
}

static void test_read_jedec(void)
{
    uint32_t jedec = 0x0;

    spi_conf(CONF_ENABLE_W0);

    spi_ctrl_start_user();
    writeb(ASPEED_FLASH_BASE, JEDEC_READ);
    jedec |= readb(ASPEED_FLASH_BASE) << 16;
    jedec |= readb(ASPEED_FLASH_BASE) << 8;
    jedec |= readb(ASPEED_FLASH_BASE);
    spi_ctrl_stop_user();

    g_assert_cmphex(jedec, ==, FLASH_JEDEC);
}

static void read_page(uint32_t addr, uint32_t *page)
{
    int i;

    spi_ctrl_start_user();

    writeb(ASPEED_FLASH_BASE, EN_4BYTE_ADDR);
    writeb(ASPEED_FLASH_BASE, READ);
    writel(ASPEED_FLASH_BASE, make_be32(addr));

    /* Continuous read are supported */
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        page[i] = make_be32(readl(ASPEED_FLASH_BASE));
    }
    spi_ctrl_stop_user();
}

static void test_erase_sector(void)
{
    uint32_t some_page_addr = 0x600 * PAGE_SIZE;
    uint32_t page[PAGE_SIZE / 4];
    int i;

    spi_conf(CONF_ENABLE_W0);

    spi_ctrl_start_user();
    writeb(ASPEED_FLASH_BASE, WREN);
    writeb(ASPEED_FLASH_BASE, EN_4BYTE_ADDR);
    writeb(ASPEED_FLASH_BASE, ERASE_SECTOR);
    writel(ASPEED_FLASH_BASE, make_be32(some_page_addr));
    spi_ctrl_stop_user();

    /* Previous page should be full of zeroes as backend is not
     * initialized */
    read_page(some_page_addr - PAGE_SIZE, page);
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        g_assert_cmphex(page[i], ==, 0x0);
    }

    /* But this one was erased */
    read_page(some_page_addr, page);
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        g_assert_cmphex(page[i], ==, 0xffffffff);
    }
}

static void test_erase_all(void)
{
    uint32_t some_page_addr = 0x15000 * PAGE_SIZE;
    uint32_t page[PAGE_SIZE / 4];
    int i;

    spi_conf(CONF_ENABLE_W0);

    /* Check some random page. Should be full of zeroes as backend is
     * not initialized */
    read_page(some_page_addr, page);
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        g_assert_cmphex(page[i], ==, 0x0);
    }

    spi_ctrl_start_user();
    writeb(ASPEED_FLASH_BASE, WREN);
    writeb(ASPEED_FLASH_BASE, BULK_ERASE);
    spi_ctrl_stop_user();

    /* Recheck that some random page */
    read_page(some_page_addr, page);
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        g_assert_cmphex(page[i], ==, 0xffffffff);
    }
}

static void test_write_page(void)
{
    uint32_t my_page_addr = 0x14000 * PAGE_SIZE; /* beyond 16MB */
    uint32_t some_page_addr = 0x15000 * PAGE_SIZE;
    uint32_t page[PAGE_SIZE / 4];
    int i;

    spi_conf(CONF_ENABLE_W0);

    spi_ctrl_start_user();
    writeb(ASPEED_FLASH_BASE, EN_4BYTE_ADDR);
    writeb(ASPEED_FLASH_BASE, PP);
    writel(ASPEED_FLASH_BASE, make_be32(my_page_addr));

    /* Fill the page with its own addresses */
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        writel(ASPEED_FLASH_BASE, make_be32(my_page_addr + i * 4));
    }
    spi_ctrl_stop_user();

    /* Check what was written */
    read_page(my_page_addr, page);
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        g_assert_cmphex(page[i], ==, my_page_addr + i * 4);
    }

    /* Check some other page. It should be full of 0xff */
    read_page(some_page_addr, page);
    for (i = 0; i < PAGE_SIZE / 4; i++) {
        g_assert_cmphex(page[i], ==, 0xffffffff);
    }
}

static char tmp_path[] = "/tmp/qtest.m25p80.XXXXXX";

int main(int argc, char **argv)
{
    int ret;
    int fd;
    char *args;

    g_test_init(&argc, &argv, NULL);

    fd = mkstemp(tmp_path);
    g_assert(fd >= 0);
    ret = ftruncate(fd, FLASH_SIZE);
    g_assert(ret == 0);
    close(fd);

    args = g_strdup_printf("-m 256 -machine palmetto-bmc "
                           "-drive file=%s,format=raw,if=mtd",
                           tmp_path);
    qtest_start(args);

    qtest_add_func("/m25p80/read_jedec", test_read_jedec);
    qtest_add_func("/m25p80/erase_sector", test_erase_sector);
    qtest_add_func("/m25p80/erase_all",  test_erase_all);
    qtest_add_func("/m25p80/write_page", test_write_page);

    ret = g_test_run();

    qtest_quit(global_qtest);
    unlink(tmp_path);
    g_free(args);
    return ret;
}
