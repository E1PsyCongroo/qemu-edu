/*
 * Copyright (c) 2006-2020, RT-Thread Development Team
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 */

#include <rthw.h>
#include <rtdevice.h>
#include <rtthread.h>

#include "board.h"
#include "drv_uart.h"

#include <stdio.h>
#ifdef RT_USING_SMART
#include <ioremap.h>
#endif
#include "sbi.h"

struct device_uart
{
    rt_ubase_t hw_base;
    rt_uint32_t irqno;
};

struct rt_serial_device serial0;
struct device_uart uart0;

void *uart8250_base = (void*)0x10010000; /* uart 1 */

static rt_uint32_t uart8250_in_freq = 24000000;
static rt_uint32_t uart8250_baudrate = 115200;
static rt_uint32_t uart8250_reg_width = 4;
static rt_uint32_t uart8250_reg_shift = 2;

static rt_uint32_t get_reg(rt_uint32_t num)
{
	rt_uint32_t offset = num << uart8250_reg_shift;

	if (uart8250_reg_width == 1)
		return __raw_readb(uart8250_base + offset);
	else if (uart8250_reg_width == 2)
		return __raw_readw(uart8250_base + offset);
	else
		return __raw_readl(uart8250_base + offset);
}

static void set_reg(rt_uint32_t num, rt_uint32_t val)
{
	rt_uint32_t offset = num << uart8250_reg_shift;

	if (uart8250_reg_width == 1)
		__raw_writeb(val, uart8250_base + offset);
	else if (uart8250_reg_width == 2)
		__raw_writew(val, uart8250_base + offset);
	else
		__raw_writel(val, uart8250_base + offset);
}


void uart_init(void)
{
    int bdiv;

    bdiv = (uart8250_in_freq + 8 * uart8250_baudrate) /
	(16 * uart8250_baudrate);

    /* Disable all interrupts */
    set_reg(UART_IER, 0x00);
    /* Enable DLAB */
    set_reg(UART_LCR, 0x80);
    
    if (bdiv) {
	    /* Set divisor low byte */
	    set_reg(UART_DLL, bdiv & 0xff);
	    /* Set divisor high byte */
	    set_reg(UART_DLH, (bdiv >> 8) & 0xff);
    }

    /* 8 bits, no parity, one stop bit */
    set_reg(UART_LCR, 0x03);
    /* Enable FIFO */
    set_reg(UART_FCR, 0x01);
    /* No modem control DTR RTS */
    set_reg(UART_MCR, 0x00);
    /* Clear line status */
    get_reg(UART_LSR);
    /* Read receive buffer */
    get_reg(UART_RHR);
    /* Set scratchpad */
    set_reg(UART_SCR, 0x00);

    return;
}

static rt_err_t _uart_configure(struct rt_serial_device *serial, struct serial_configure *cfg)
{
    uart_init();
    return (RT_EOK);
}

static rt_err_t _uart_control(struct rt_serial_device *serial, int cmd, void *arg)
{
    struct device_uart *uart = (struct device_uart*)serial->parent.user_data;

    switch (cmd)
    {
    case RT_DEVICE_CTRL_CLR_INT:
        if ((size_t)arg == RT_DEVICE_FLAG_INT_RX)
        {
            rt_uint8_t value = get_reg(UART_IER);
            set_reg(UART_IER, value & ~UART_IER_RX_ENABLE);
        }
        break;

    case RT_DEVICE_CTRL_SET_INT:
        if ((size_t)arg == RT_DEVICE_FLAG_INT_RX)
        {
            rt_uint8_t value = get_reg(UART_IER);
            set_reg(UART_IER, value | UART_IER_RX_ENABLE);
        }
        break;
    }

    return (RT_EOK);
}

static int _uart_putc(struct rt_serial_device *serial, char c)
{
    struct device_uart *uart;
    uart = (struct device_uart*)serial->parent.user_data;

    // wait for Transmit Holding Empty to be set in LSR.
    while((get_reg(UART_LSR) & UART_LSR_TX_IDLE) == 0)
        ;
    set_reg(UART_THR, c);

    return (1);
}

static int _uart_getc(struct rt_serial_device *serial)
{
    struct device_uart *uart;
    volatile rt_uint32_t lsr;
    int ch = -1;

    uart = (struct device_uart*)serial->parent.user_data;
    lsr = get_reg(UART_LSR);

    if (lsr & UART_LSR_RX_READY)
    {
        ch = get_reg(UART_RHR);
    }
    return ch;
}

const struct rt_uart_ops _uart_ops = {
    _uart_configure,
    _uart_control,
    _uart_putc,
    _uart_getc,
    // TODO: add DMA support
    RT_NULL};

static void rt_hw_uart_isr(int irqno, void *param)
{
    rt_ubase_t level = rt_hw_interrupt_disable();

    struct rt_serial_device *serial = (struct rt_serial_device *)param;

    rt_hw_serial_isr(serial, RT_SERIAL_EVENT_RX_IND);

    rt_hw_interrupt_enable(level);
}

/*
 * UART Initiation
 */
int rt_hw_uart_init(void)
{
    struct rt_serial_device *serial;
    struct device_uart *uart;
    struct serial_configure config = RT_SERIAL_CONFIG_DEFAULT;
#ifdef RT_USING_SMART
    uart0_base = rt_ioremap(uart8250_base, 4096);
#endif
    // register device
    serial = &serial0;
    uart = &uart0;

    serial->ops = &_uart_ops;
    serial->config = config;
    serial->config.baud_rate = UART_DEFAULT_BAUDRATE;
    uart->hw_base = (rt_ubase_t)uart8250_base;
    uart->irqno = 33;

    rt_hw_serial_register(serial,
                          RT_CONSOLE_DEVICE_NAME,
                          RT_DEVICE_FLAG_STREAM | RT_DEVICE_FLAG_RDWR | RT_DEVICE_FLAG_INT_RX,
                          uart);
    rt_hw_interrupt_install(uart->irqno, rt_hw_uart_isr, serial, RT_CONSOLE_DEVICE_NAME);
    rt_hw_interrupt_umask(uart->irqno);
    return 0;
}

/* WEAK for SDK 0.5.6 */
rt_weak void uart_debug_init(int uart_channel)
{
}
