rule AISURU
{
    meta:
        description = "Detects AISURU Stealer"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256 = ""

        // --- cfgx --------------------------------------------------------------
        algo              = "rc4"    // plain RC4 per entry (see plugin.py)
        key_size          = 16       // `push 10h`: first `push offset` after it is the key, the second is the RC4 state
        config_size_at    = 1        // `push 0Ah` (byte 1 of the match) = length of the entry
        config_size_bytes = 1
    strings:

        $key = {
            51                         //             push    ecx
            6A 10                      //             push    10h
            68 ?? ?? ?? ??             //             push    offset unk_805A5A0
            68 ?? ?? ?? ??             //             push    offset byte_805D8A0
            E8 ?? ?? ?? ??             //             call    RC4_Key_sch    

        }

        $config = {
            6A ?? [0-3]                //             push    0Ah
            68 ?? ?? ?? ??             //             push    offset unk_805A6C0
            50                         //             push    eax
            E8 ?? ?? ?? ??             //             call    sub_8053030

        }


    condition:
        uint16(0) == 0x457f // ELF header
        and filesize < 5MB 
        and $key
        and $config
}



rule AISURU_V2
{
    meta:
        description = "Detects AISURU Stealer"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256 = ""

        // --- cfgx --------------------------------------------------------------
        algo               = "aisuru_v2"   // key schedule sub_804D070 + the custom PRGA (verified on real samples)
        key_size           = 16
        key_deref          = true      // `mov edx, ds:off_805BD48` is a POINTER VARIABLE: follow it to the key string
        config_size_at     = 6         // `mov ecx, 0Ch` (byte 6 of the match) = number of DWORDS copied by rep movsd
        config_size_bytes  = 1
        config_size_mul    = 4         // DWORDS -> bytes
        config_size_tail   = "F3A5 66A5=2 A4=1"   // + 2 for a following `movsw`, + 1 for a following `movsb`
        config2_size_at    = 2         // `push 8Eh` (byte 2 of the match) = length of the blob
        config2_size_bytes = 1
        config2_size_mul   = 1         // (config2 would otherwise inherit config_size_mul)
    strings:

        $key = {
            B9 10 00 00 00     //     mov     ecx, 10h
            8B ?? ?? ?? ?? ??  //     mov     edx, ds:off_805BD48 ; "PJbiNbbeasddDfsc"
            89 ??              //     mov     eax, esi
            E8 ?? ?? FF FF     //     call    sub_804D070

        }

        $config = {
            BE ?? ?? ?? ??        //                  mov     esi, offset unk_805BC60
            B9 ?? [0-3]        //                  mov     ecx, 0Ch
            F3 A5                 //                  rep movsd
            [0-8]          //                  mov     byte ptr [eax+30h], 0
            A? ?? ?? ?? ??        //                  mov     eax, ds:dword_805D774

        }
        $config2 =
        {
            5?                       //               push    eax
            6? ?? [0-3]              //               push    8Eh
            68 ?? ?? ?? ??           //               push    offset unk_805BCB8
            5?                       //               push    esi
            E8 ?? ?? ?? ??           //               call    sub_8059000
        }


    condition:
        uint16(0) == 0x457f // ELF header
        and filesize < 5MB 
        and $key
        and ($config or $config2)
}


rule AISURU_ARM_V
{
    meta:
        description = "Detects AISURU Stealer"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256 = ""

        // --- cfgx --------------------------------------------------------------
        algo             = "auto"    // routine one is standard RC4; "auto" also tries the custom cipher
        key_size         = 16
        key_ref_index    = 1         // 2nd literal load (`LDR R1,=key`); the 1st is the RC4 state (R0)
        config_ref_index = 1         // 2nd literal load = the data
        config_size_reg  = "r2"      // `MOV R2,#0x10` before the BL
    strings:

        $key = {
            2C ?0 ?? E5    //         LDR     R0, =byte_29F6C
            2C ?0 ?? E5    //         LDR     R1, =unk_1BAE0
            10 ?0 ?? E3    //         MOV     R2, #0x10
            ?? ?? ?? EB    //         BL      sub_8CF0

        }

        $config = {
            30 ?0 ?? E5       //                      LDR     R0, =byte_29F6C
            30 ?0 ?? E5       //                      LDR     R1, =unk_1BAE0
            10 ?0 ?? E3       //                      MOV     R2, #0x10
            ?? ?? ?? EB       //                      BL      sub_8CF0
        }
      


    condition:
        uint16(0) == 0x457f // ELF header
        and filesize < 5MB 
        and $key
        and $config
}
