# Research tools related to Intel Wi-Fi chips

This project contains tools which:

- decode Intel Wi-Fi firmware files (the `iwlwifi-...ucode` files in the [`linux-firmware` git repository](https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git/tree/))
- communicate with the chip through Linux's debug filesystem (`/sys/kernel/debug/iwlwifi/...`)
- ...

It is part of a work which was presented at SSTIC 2022: <https://www.sstic.org/2022/presentation/intel_wifi/>
