.code

public _cr4_get
public _cr4_set


_cr4_get:

    mov     rax, cr4    
    ret


_cr4_set:

    and     rcx, 0FFFFFFFFh
    mov     cr4, rcx
    ret


end
