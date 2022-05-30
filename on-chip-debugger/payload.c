#include <stdbool.h>
#include <stdint.h>

#ifdef LMAC
#define SB_CPU_1_STATUS                      0xA01E30
#define SB_CPU_2_STATUS                      0xA01E34
#define MON_BUFF_BASE_ADDR                   0xA03C3C
#define LMPM_SECURE_UCODE_LOAD_CPU1_HDR_ADDR 0xA01E78
#define LMPM_SECURE_UCODE_LOAD_CPU2_HDR_ADDR 0xA01E7C
#elif defined UMAC
#define SB_CPU_1_STATUS                      0xC0A01E30
#define SB_CPU_2_STATUS                      0xC0A01E34
#define MON_BUFF_BASE_ADDR                   0xC0A03C3C
#define LMPM_SECURE_UCODE_LOAD_CPU1_HDR_ADDR 0xC0A01E78
#define LMPM_SECURE_UCODE_LOAD_CPU2_HDR_ADDR 0xC0A01E7C
#else
#error "LMAC/UMAC is undefined"
#endif

#define CMD_NONE            0
#define CMD_CONTINUE        3
#define CMD_READ_REG        4
#define CMD_READ_MEM1       0x6789
#define CMD_READ_MEM2       0x678a
#define CMD_READ_MEM4       0x678b
#define CMD_WRITE_MEM1      0x1234 /* prevent jump table from being generated */
#define CMD_WRITE_MEM2      0x1235 /* prevent jump table from being generated */
#define CMD_WRITE_MEM4      0x1236 /* prevent jump table from being generated */
#define CMD_DISABLE_HOOK    0xd34d

static inline uint32_t read_arc_reg(int n)
{
  uint32_t value;

  switch (n) {
  case 4:
    asm("mov %0, r4" : "=r"(value) :: "r4"); break;
  case 32:
    asm("mov %0, r32" : "=r"(value) :: "r32"); break;
  default:
    value = 0xdeadbeef;
    break;
  }

  return value;
}

static inline uint32_t read_reg(volatile uint32_t *reg)
{
  return *reg;
}

static inline void write_reg(volatile uint32_t *reg, uint32_t value)
{
  *reg = value;
}

static inline uint32_t inc_reg(volatile uint32_t *reg)
{
  uint32_t previous_value = read_reg(reg);
  write_reg(reg, previous_value + 1);
  return previous_value;
}

void blah(void)
{
  volatile uint32_t *R_ARG1 = (volatile uint32_t *)SB_CPU_1_STATUS;
  volatile uint32_t *R_ARG2 = (volatile uint32_t *)SB_CPU_2_STATUS;
  volatile uint32_t *R_OUT = (volatile uint32_t *)MON_BUFF_BASE_ADDR;
  volatile uint32_t *R_PING = (volatile uint32_t *)LMPM_SECURE_UCODE_LOAD_CPU1_HDR_ADDR;
  volatile uint32_t *R_CMD = (volatile uint32_t *)LMPM_SECURE_UCODE_LOAD_CPU2_HDR_ADDR;

  /* disable this hook once the command is set to CMD_DISABLE_HOOK */
  if (read_reg(R_CMD) == CMD_DISABLE_HOOK) {
    return;
  }

// increase the watchdog delay (I guess)
#ifdef LMAC
  *(volatile int *)0x00a020dc = 200000 * 10;
#elif defined UMAC
  *(volatile int *)0xc0a020e0 = 200000 * 1000;
#endif

  write_reg(R_CMD, CMD_NONE);

  /* tell the host there is a new interrupt */
  inc_reg(R_PING);

  /* read commands */
  bool stop = false;
  uint32_t reg;
  uint32_t value;
  uint32_t command;
  uint32_t addr;

  while (!stop) {
    /* wait for command */
    while (1) {
      command = read_reg(R_CMD);
      if (command != CMD_NONE) {
        break;
      }
    }

    /* reset cmd */
    if (command != CMD_DISABLE_HOOK) {
      write_reg(R_CMD, CMD_NONE);
    }

    switch (command) {
    case CMD_DISABLE_HOOK:
    case CMD_CONTINUE:
      stop = true;
      break;

    case CMD_READ_REG:
      /* read reg number */
      reg = read_reg(R_ARG1);

      /* read register and transfer it through in */
      value = read_arc_reg(reg);
      write_reg(R_OUT, value);
      break;

    case CMD_READ_MEM1:
    case CMD_READ_MEM2:
    case CMD_READ_MEM4:
      /* read address */
      addr = read_reg(R_ARG1);

      /* read memory and transfer it through in */
      if (command == CMD_READ_MEM1) {
        value = *(uint8_t *)addr;
      } else if (command == CMD_READ_MEM2) {
        value = *(uint16_t *)addr;
      } else {
        value = *(uint32_t *)addr;
      }
      write_reg(R_OUT, value);
      break;

    case CMD_WRITE_MEM1:
    case CMD_WRITE_MEM2:
    case CMD_WRITE_MEM4:
      /* read address */
      addr = read_reg(R_ARG1);
      value = read_reg(R_ARG2);

      /* write value to memory */
      if (command == CMD_WRITE_MEM1) {
        *(uint8_t *)addr = value;
      } else if (command == CMD_WRITE_MEM2) {
        *(uint16_t *)addr = value;
      } else {
        *(uint32_t *)addr = value;
      }
      break;
    }

    /* tell it's ready */
    inc_reg(R_PING);
  }
}
