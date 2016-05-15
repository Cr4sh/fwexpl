.code

public _invlpg
public _cr3_get
public _cr3_set

_SMM SEGMENT EXECUTE READ 'CODE'

_invlpg PROC

    invlpg  [rcx]
    ret

_invlpg ENDP

_cr3_get PROC

    mov     rax, cr3    
    ret

_cr3_get ENDP

_cr3_set PROC

    mov     cr3, rcx    
    ret

_cr3_set ENDP

_SMM ENDS


end
