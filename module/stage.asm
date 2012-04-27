BITS 32

; push EIP and GP registers
	call SAVEIP
SAVEIP:
	pusha

; call mmap 
	xor eax,eax
	mov al,192	; mmap2
  	xor ebx,ebx	; ul page aligned address
	xor ecx,ecx
  	mov ch,0x80	; 8192 ul page aligned len (file size) 	
 	cdq		; xor edx,edx
  	mov dl,0x7 	; ul prot rwx
	mov esi,0x22	; l flags MAP_PRIVATE 0x02|MAP_ANONYMOUS 0x20 
	int 0x80	;	

    shr ecx,1;
    add eax,ecx ; set it at half page
; setup pattern / copy code
	mov word [eax], 0xe0ff ; jmp eax NOTE endianness
	
; jump to page
	jmp eax


