entry:
  push_s  blink
  push_s  r0
  push_s  r1
  push_s  r2
  push_s  r3
  push    r4
  push    r5
  push    r6
  push_s  r12
  push_s  r13
  push_s  r14
  push_s  r15
  ;; push    r36
  bl      blah                  ; jump to the payload
  ;; pop     r36
  pop_s   r15
  pop_s   r14
  pop_s   r13
  pop_s   r12
  pop     r6
  pop     r5
  pop     r4
  pop_s   r3
  pop_s   r2
  pop_s   r1
  pop_s   r0
  pop_s   blink

  mov_s   r1, 0xdeadbeef        ; jump to the original function (address patched)
  j_s     [r1]

blah:
