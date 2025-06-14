# NVM dumps from wireless AC 9560 chip (on Lenovo T490)

```sh
for i in /sys/kernel/debug/iwlwifi/0000:00:14.3/iwlmvm/{nvm*,sram} ; do
    cat "$i" > "${i##*/}.bin"
done
```
