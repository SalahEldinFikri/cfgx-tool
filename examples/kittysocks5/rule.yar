rule kittysocks5
{
    meta:
        description = "Detects kittysocks5 Malware"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256 = ""

        // --- cfgx --------------------------------------------------------------
        key_size         = 16        // $key: `LDR R3,=table_key` -> 16 bytes
        config_ref_index = "all"     // $config: every `LDR R1,=entry` is a separate entry
        config_size_reg  = "r2"      // entry length = value of R2 at the following BL (MOV/ADD R2,#n)
    strings:
        $key = {
            ?? ?0 9? E5                    //         LDR     R3, =table_key
            0? ?0 D? E7                    //         LDRB    R3, [R3,R2]
            0? ?0 2? E0                    //         EOR     R3, R0, R3
            FF ?0 0? E2                    //         AND     R3, R3, #0xFF
            00 ?0 ?? E5                    //         STRB    R3, [R12]
            ?? ?0 1? E5                    //         LDR     R3, [R11,#var_14]
            0? ?0 8? E2                    //         ADD     R3, R3, #1
            ?? ?0 0? E5                    //         STR     R3, [R11,#var_14]
        }


        $config = {
            ?? 00 A0 E3   //         MOV     R0, #7
            ?? 10 9F E5   //         LDR     R1, =byte_205E0
            ?? ?? A0 E3 [0-4]   //         MOV     R2, #0x11
            ?? ?? ?? EB   //         BL      add_entry
        }

    condition:
        uint16(0) == 0x457f // ELF header
        and filesize < 5MB 
        and $key
        and $config
}

rule kittysocks5_v2
{
    meta:
        description = "Detects kittysocks5 Malware"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256 = ""

        // --- cfgx --------------------------------------------------------------
        // $config2 inherits the config_* settings (it is a variant of $config), so these
        // three lines cover both patterns.
        key_size         = 16        // $key: `LDR R4,=table_key` -> 16 bytes
        config_ref_index = "all"     // every `LDR R1,=entry` is a separate entry
        config_size_reg  = "r2"      // entry length = value of R2 at the following BL
    strings:

    $key = {
        ?? ?? 9? E5            //                 LDR     R4, =table_key
        0? ?0 A? E3            //                 MOV     R12, #0
                               // loc_D964  (loop start)
        CC ?F ?? E1            //                 MOV     R3, R12,ASR#31
        2? ?E ?? E1            //                 MOV     R3, R3,LSR#28
        0? ?0 ?? E0            //                 ADD     R2, R12, R3
        00 ?0 ?? E5            //                 LDR     R0, [LR]
        0F ?0 0? E2            //                 AND     R2, R2, #0xF
    }

    $config = {
        ?? 10 9F E5                 //            LDR     R1, =unk_1BF00
        ?? ?? A0 E3                 //            MOV     R2, #0x7D ; '}'
        ?? ?? ?? EB                 //            BL      util_memcpy
    }

    $config2 = {
        ?? 10 9F E5               //              LDR     R1, =unk_1BF80
        ?? ?? A0 E?               //              MOV     R2, #0xA
        ?? ?? A0 E?               //              MOV     R5, R0
        ?? ?? ?? EB               //              BL      util_memcpy
    }


    condition:
        uint16(0) == 0x457f // ELF header
        and filesize < 5MB 
        and $key
        and ($config or $config2)
        
}


rule kittysocks5_Mips_Version
{
    meta:
        description = "Detects kittysocks5 Malware"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256 = ""

        // --- cfgx --------------------------------------------------------------
        key_size         = 16        // $key: `la $v0, table_key` (GOT load via $gp) -> 16 bytes
        config_ref_index = 0         // $config: the FIRST reference is the entry (`addiu $a1,$v0,off`);
                                     //   "all" also works, but then cfgx tries the function pointer built
                                     //   for jalr $t9 as well and has to skip it (no length for it)
        config_size_reg  = "a2"      // entry length = value of $a2 at the call (`li $a2, N`, delay slot included)
        // mips_gp = 0x4a0ff0        // only if cfgx cannot find $gp itself: the value of _gp (see the warning)

    strings:
        $key = {
            8F 82 ?? ??          // la $v0, table_key
            [0-4]
            00 43 10 21          // addu $v0, $v1
            90 42 00 00          // lbu $v0, 0($v0)
            [0-4]
            00 02 16 00          // sll $v0, $v0, 24
            00 02 16 03          // sra $v0, $v0, 24
            8F C3 ?? ??          // lw $v1, var($fp)
            [0-4]
            00 62 10 26          // xor $v0, $v1, $v0
            00 02 16 00          // sll $v0, $v0, 24
            00 02 16 03          // sra $v0, $v0, 24
            8F C3 ?? ??          // lw $v1, var($fp)
            [0-4]
            A0 62 00 00          // sb $v0, 0($v1)
            8F C2 ?? ??          // lw $v0, var($fp)
            [0-4]
            24 42 00 01          // addiu $v0, $v0, 1

        }

        $config = {
            24 45 ?? ??          // addiu $a1, $v0, offset
            24 06 00 ??          // li $a2, ';'
            8F 82 ?? ??          // la $v0, loc_410000
            00 00 00 00          // nop
            24 59 ?? ??          // addiu $t9, $v0, offset
            03 20 F8 09          // jalr $t9
        }
    condition:
        uint16(0) == 0x457f // ELF header
        and filesize < 5MB 
        and $key
        and $config
}
