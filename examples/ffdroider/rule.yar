rule FFDroider 
{
    meta:
        description = "Detects FFDroider Family"
        author      = "SalahEldin Fikri (Mr_MaTriX)"

    strings:
        $m1 = "37238328-1324242-5456786-8fdff0-67547552436675" ascii wide
        $m2 = "FFDroider" ascii wide
        $m3 = "FDroid1" ascii wide
        $m4 = "Software\\ffdroider" ascii wide
     

        $data = {
            6A 00                //   push    0
            68 ?? ?? ?? ??       //   push    offset aIifleciLVq ; "IiflEci~l|vQ"
            E8 ?? ?? ?? ??       //   call    decryption
            [0-24]                   //   push    edx             ; hModule
            FF 15 ?? ?? ?? ??    //   call    ds:GetProcAddress
            89 ?? ??             //   mov     [ebp+var_18], eax
        }
        $data2 = {
            6A ??                //    push    0
            68 ?? ?? ?? ??       //    push    offset aKcsiyc8Jc ; "kcsiyc8>#jc|"
            E8 ?? ?? ?? ??       //    call    decryption
            [0-24]
            FF 55 ??             //    call    [ebp+var_18]
            89 ?? ??             //    mov     [ebp+hModule], eax
        }
        

        
    condition:
        uint16(0) == 0x5A4D // MZ header
        and filesize < 5MB 
        and any of ($m*)
        and ($data or $data2)
        
}
