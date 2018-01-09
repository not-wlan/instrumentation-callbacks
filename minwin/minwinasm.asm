include ksamd64.inc
EXTERN hook:NEAR
.data 
	value qword ?
.code

medium  PROC
	
	; https://docs.microsoft.com/en-us/cpp/build/caller-callee-saved-registers

	push rax ; return value
	push rcx
	push RBX
	push RBP
	push RDI
	push RSI
	push RSP
	push r10
	push r11
	push R12
	push R13
	push R14
	push R15 

	; without this it crashes :)
	sub rsp, 1000h
	mov rdx, rax
	mov rcx, r10
	call hook
	mov QWORD PTR [value], rax
	add rsp, 1000h

	pop R15 
	pop R14
	pop R13
	pop R12
	pop R11
	pop R10
	pop RSP
	pop RSI
	pop RDI
	pop RBP
	pop RBX
	pop rcx
	pop rax
	mov rax, qword ptr [value]

    jmp R10
medium  ENDP
 
END