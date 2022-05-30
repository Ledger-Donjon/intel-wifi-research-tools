entry:
  ;; call the original function (address patched)
  push_s  blink
  mov_s   r0, 0xdeadbeef
  jl_s    [r0]
  pop_s   blink

  ;; notify the emulator that the original function returned
  trap_s  0x1
  ;;   b start
