.code

public _invlpg
public _cr3_get
public _cr3_set
public _vmread

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

_vmread PROC

    vmread  rax, rcx    
    ret

_vmread ENDP

_SMM ENDS

end
