import "pe"

rule Family_Vulcan
{
    meta: 
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        // cfgx: pure detection rule, nothing to extract (hides its ~30 marker strings)
        family  = "Vulcan"
        extract = "none"
    strings:
        $m1 = "vulcan/implant/attacks" ascii wide 
        $m2 = "vulcan_386" ascii wide
        $m3 = "vulcan_mips" ascii wide
        $m4 = "vulcan_arm7" ascii wide
        $m5 = "vulcan_amd64" ascii wide
        $m6 = "vulcan_arm64" ascii wide
        $m7 = "vulcan-agent" ascii wide
        $m8 = "VULCAN_UPDATERno renegotiation" ascii wide
        $m9 = "vulcan-updater.service" ascii wide
        $m10 = "Description=VULCAN System Updater\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=30\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=default.target\n[Unit]\nDescription=VULCAN System Updater\nAfter=network.target\n\n[Service]\nType=simple\nExecStart=%s\nRestart=always\nRestartSec=30\nStandardOutput=null\nStandardError=null\n\n[Install]\nWantedBy=multi-user.target\n" ascii wide
        $m11 = "vulcan/implant" ascii wide

        $s1  = "[DEBUG] Dial error: %v\n" ascii wide 
        $s2  = "[DEBUG] Read error: %v\n" ascii wide 
        $s3  = "[DEBUG] readLoop started" ascii wide 
        $s4  = "[DEBUG] Write error: %v\n" ascii wide 
        $s5  = "[DEBUG] Scanning enabled" ascii wide 
        $s6  = "[DEBUG] Invalid URL: %v\n" ascii wide 
        $s7  = "[DEBUG] Implant starting...insufficient security level" ascii wide 
        $s8  = "[DEBUG] Self-destruct initiatedbad certificate status responseencrypted client hello required" ascii wide 
        $s9  = "GODEBUG sys/cpu: value \"" ascii wide 
        $s10 = "GODEBUG: can not enable \"" ascii wide         
        $s12 = "GODEBUG: unknown cpu feature \"" ascii wide 
        $s13 = "GODEBUG: no value specified for \""
        $s14 = "[DEBUG] Read error: %v\nunsupported certificateno application protocol"
        $s15 = "[DEBUG] readLoop started"
        $s16 = "[DEBUG] Dial error: %v\n"
        $s17 = "[DEBUG] Scanning enabled"
        $s18 = "[DEBUG] Invalid URL: %v\nerror decrypting messagecertificate unobtainable"
        $s19 = "[DEBUG] Worker %d EXITED\n"
        $s20 = "[DEBUG] Scanning disabled"

    condition:
    uint32(0) == 0x464c457f and
    (any of ($m*)) and
    (10 of ($s*))
    
}


rule version_386_elf
{
    meta:
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        // cfgx: no encryption. $Config = pointer (lea eax,[str]) + length (the 13h of
        // mov [esp+4],13h = byte 13 of the match, 4 bytes little-endian)
        family = "Vulcan"
        Config_size_at = 13
    strings:

    $Config = {
             8D 05 ?? ?? ?? ??                             // lea     eax, a14619213198844 ; "146.19.213.198:8443revoked certificatee"...
             89 04 24                                      // mov     [esp+5Ch+localip], eax ; int
             C7 44 24 04 13 00 00 00                       // mov     [esp+5Ch+p_main_Implant.ptr], 13h ; int
             8B 44 24 34                                   // mov     eax, [esp+5Ch+var_28]
             89 44 24 08                                   // mov     [esp+5Ch+p_main_Implant.len], eax ; int
             E8 ?? ?? ?? ??                                // call    main_NewC2Connection
        }

    condition:
        any of them
}


rule version_amd64
{
    meta:
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        // cfgx: length = imm32 of `mov ebx, 13h` (byte 8 of the match)
        family = "Vulcan"
        Config_size_at = 8
    strings:
    $Config = {
            48 8D 05 ?? ?? ?? ??                 //   lea     rax, a14619213198844 ; "146.19.213.198:8443revoked certificatee"...
            BB 13 00 00 00                       //   mov     ebx, 13h
            48 8B 4C 24 58                       //   mov     rcx, [rsp+0B0h+var_58]
            E8 ?? ?? ?? ??                       //   call    main_NewC2Connection
    }
    condition:
        any of them
}



rule version_arm5
{
    meta:
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        // cfgx: pointer = LDR R0,=str (literal pool); length = imm8 of MOV R0,#0x13 (byte 8, 1 byte)
        family = "Vulcan"
        Config_size_at = 8
        Config_size_bytes = 1
    strings:
    $Config = {
            48 02 ?? ??                         //    LDR             R0, =a14619213198844 ; "146.19.213.198:8443revoked certificatee"...
            04 00 8D E5                         //    STR             R0, [SP,#0x60+var_5C] ; int
            13 00 A0 E3                         //    MOV             R0, #0x13
            08 00 8D E5                         //    STR             R0, [SP,#0x60+var_58] ; int
            38 00 9D E5                         //    LDR             R0, [SP,#0x60+var_28]
            0C 00 8D E5                         //    STR             R0, [SP,#0x60+var_54] ; int
            3D ?? ?? ??                         //    BL              main.NewC2Connection
    }
    condition:
        any of them
}


rule version_arm7
{
    meta:
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        family = "Vulcan"
        Config_size_at = 8
        Config_size_bytes = 1
    strings:
    $Config = {
            44 02 ?? ??            // LDR             R0, =a14619213198844 ; "146.19.213.198:8443revoked certificatee"...
            04 00 8D E5            // STR             R0, [SP,#0x60+var_5C] ; int
            13 00 A0 E3            // MOV             R0, #0x13
            08 00 8D E5            // STR             R0, [SP,#0x60+var_58] ; int
            38 00 9D E5            // LDR             R0, [SP,#0x60+var_28]
            0C 00 8D E5            // STR             R0, [SP,#0x60+var_54] ; int
            59 ?? ?? ??            // BL              main.NewC2Connection
    }
    condition:
        any of them
}


rule version_mips
{
    meta:
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        // cfgx: pointer = lui+addiu pair; length = 16-bit immediate of `li $at,0x13`
        // (bytes 14..15, big-endian: taken from the ELF header automatically)
        family = "Vulcan"
        Config_size_at = 14
        Config_size_bytes = 2
    strings:
    $Config = {
            3C 01 00 51 24 21 ?? ??         // li      $at, a14619213198844  # "146.19.213.198:8443revoked certificatee"...
            AF A1 00 04                     // sw      $at, 0x68+var_64($sp)  # int
            24 01 00 13                     // li      $at, 0x13
            AF A1 00 08                     // sw      $at, 0x68+var_60($sp)  # int
            8F A1 00 40                     // lw      $at, 0x68+var_28($sp)
            AF A1 00 0C                     // sw      $at, 0x68+var_5C($sp)  # int
            0C ?? ?? ??                     // jal     main_NewC2Connection
    }
    condition:
        any of them
}


rule version_mipsle
{
    meta:
        discription = "Detects Family Vulcan Malware"
        author = "SalahEldin Kamil (Mr_MaTriX)"

        // cfgx: little-endian MIPS: length = 16-bit immediate at bytes 12..13
        family = "Vulcan"
        Config_size_at = 12
        Config_size_bytes = 2
    strings:
    $Config = {
            51 00 01 3C ?? ?? 21 24            //     li      $at, a14619213198844  # "146.19.213.198:8443revoked certificatee"...
            04 00 A1 AF                        //     sw      $at, 0x64+var_60($sp)  # int
            13 00 01 24                        //     li      $at, 0x13
            08 00 A1 AF                        //     sw      $at, 0x64+var_5C($sp)  # int
            3C 00 A1 8F                        //     lw      $at, 0x64+var_28($sp)
            0C 00 A1 AF                        //     sw      $at, 0x64+var_58($sp)  # int
            ?? ?? ?? 0C                        //     jal     main_NewC2Connection
    }
    condition:
        any of them
}
