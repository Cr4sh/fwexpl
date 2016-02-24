.code

public GetCPUIDFeatureBits

GetCPUIDFeatureBits:

    push    rax
    push    rdi
    push    rsi    
    push    rdx
    push    rcx    
    
    mov     rax, rcx            ; query CPU info of desired type
    mov     rcx, 0
    cpuid

    mov     rsi, rcx
    mov     rdi, rdx
    mov     rax, rbx
    
    pop     rcx
    pop     rdx    

    mov     [rdx], esi          ; save CPUID.RCX
    mov     [r8], edi           ; save CPUID.RDX
    mov     [r9], eax           ; save CPUID.RBX

    pop     rsi
    pop     rdi
    pop     rax
    ret

end
