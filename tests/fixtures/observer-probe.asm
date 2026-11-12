bits 16
org 0x100

; The generated program owns its conventional-memory block. Relocate the
; bounded probe to a fixed address so its capture plan needs no loader map.
push cs
pop ds
mov ax, 0x8000
mov es, ax
xor di, di
mov si, payload
mov cx, payload_end - payload
cld
rep movsb
jmp 0x8000:0

payload:
push cs
pop ds
mov ax, 0x0013
int 0x10
mov ax, 0xa000
mov es, ax
xor di, di
mov cx, 64000
mov al, 3
rep stosb
mov dx, 0x3c8
xor al, al
out dx, al
inc dx
mov al, 63
out dx, al
xor al, al
out dx, al
out dx, al

; Request a short unsigned eight-bit DMA playback on the synthetic SB profile.
mov dx, 0x226
mov al, 1
out dx, al
xor al, al
out dx, al
mov dx, 0x22e
mov cx, 10000
.reset_wait:
in al, dx
test al, 0x80
loopz .reset_wait
mov dx, 0x22a
in al, dx
cmp al, 0xaa
jne .failed
mov al, 5
out 0x0a, al
xor al, al
out 0x0c, al
out 0x02, al
mov al, 4
out 0x02, al
mov al, 8
out 0x83, al
mov al, 63
out 0x03, al
xor al, al
out 0x03, al
mov al, 0x49
out 0x0b, al
mov al, 1
out 0x0a, al
mov di, 0x400
push ds
pop es
mov cx, 64
mov al, 0x80
rep stosb
mov al, 0x40
call .send
mov al, 0xd3
call .send
mov al, 0x14
call .send
mov al, 63
call .send
xor al, al
call .send
sti
mov cx, 5
.wait:
hlt
loop .wait
mov word [0x300], 0x1234
jmp .stop
.failed:
mov word [0x300], 0xffff
.stop:
mov ax, 0xbeef
jmp $

.send:
push ax
mov dx, 0x22c
mov cx, 10000
.ready:
in al, dx
test al, 0x80
loopnz .ready
pop ax
out dx, al
ret
payload_end:
