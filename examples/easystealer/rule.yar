rule EasyStealer {
    meta:
        description = "Detects EasyStealer Malware"
        author      = "SalahEldin Fikri (Mr_MaTriX)"
        SHA256      = ""

        // --- cfgx: no encryption here, so no plugin is needed -----------------
        // Go strings are not NUL-terminated; the C2 is a pointer (lea eax,[str])
        // plus a length (mov [esp+4], 0Dh) taken from the code itself.
        extract    = "c2"      // only read $c2 (the $m* strings are just detection)
        c2_size_at = 25        // byte 25 of the match = the immediate of C7 44 24 04 0? 00 00 00

    strings:
        $m1  = "easy/decrypt.Start" ascii wide
        $m2  = "easy/decrypt.Start.func1" ascii wide
        $m3  = "easy/decrypt.GetMePath" ascii wide
        $m4  = "easy/decrypt.RandomString" ascii wide
        $m5  = "easy/decrypt.FoundBrowser" ascii wide
        $m6  = "easy/decrypt.GrabFromBrowser" ascii wide
        $m7  = "easy/decrypt.GrabFromBrowser.func1" ascii wide
        $m8  = "easy/decrypt.MasterKey" ascii wide
        $m9  = "easy/user.EX" ascii wide
        $m10 = "easy/user.Return" ascii wide
        $m11 = "easy/user.init.0" ascii wide
        $m12 = "easy/user.GetHWID" ascii wide
        $m13 = "easy/user.SystemInfo" ascii wide
        $m14 = "easy/user.init" ascii wide
        $m15 = "easy/zip.addFiles" ascii wide

        $c2 = {
                C7 04 24 ?? 00 00 00        // 0..6    mov  [esp+8+var_8], 13h
                E8 ?? ?? ?? ??              // 7..11   call log_SetFlags
                8D 05 ?? ?? ?? ??           // 12..17  lea  eax, <string blob>      <- pointer
                89 ?? ??                    // 18..20  mov  [esp+8+var_8], eax
                C7 44 24 04 0? 00 00 00     // 21..28  mov  [esp+8+var_4], 0Dh      <- length at byte 25
                E8 ?? ?? ?? ??              // 29..33  call easy_network_InitServer
        }

    condition:
        uint16(0) == 0x5A4D // MZ header
        and filesize < 10MB
        and $c2
        and 10 of ($m*)
}
