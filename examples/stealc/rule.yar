rule StealcStealer
{
    meta:
        description = "Detect Stealc Stealer Family"
        author      = "SalahEldin Kamil (Mr_MaTriX)"
        family      = "Stealc"

        // --- cfgx: how to read the encrypted strings -------------------------
        // Every reference inside $data_* is a different encrypted string, so
        // follow all of them (default would follow only the first).
        data_32_ref_index = "all"
        data_64_ref_index = "all"
        // $key_32 / $key_64 need nothing: first reference, read up to the NUL.

        // Only for running WITHOUT a plugin (shows what the rule located): hide s*/m*.
        extract = "key_*,data_*"

    strings:
        // Builder path artefacts (strong family IOC)
        $s1 = "C:\\builder_v2\\stealc\\json.h" ascii wide
        $s2 = "C:\\builder_v3\\build\\json.h" ascii wide

        // GUID format string present in all builds
        $m1 = "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX" ascii wide

        // PE32 (x86): RC4 init stub  -> the key.   (was $rc4_32)
        $key_32 = {
            6A 12                   // push 12h (key length)
            68 ?? ?? ?? ??          // push offset key_string
            B9 ?? ?? ?? ??          // mov ecx, offset rc4_state
            E8 ?? ?? ?? ??          // call rc4_init
        }

        // PE32 (x86): Base64+RC4 decrypt call pair -> the data
        $data_32 = {
            68 ?? ?? ?? ??          // push offset ciphertext_b64
            8D 4? ??                // lea ecx, [ebp+local_buf]
            E8 ?? ?? ?? ??          // call base64_decode
            8D 5? ??                // lea edx, [ebp+decoded]
            8D 4? ??                // lea ecx, [ebp+output]
            E8 ?? ?? ?? ??          // call rc4_decrypt
        }

        // PE64 (x64): RC4 init stub  -> the key.   (was $RC4_64)
        $key_64 = {
            4C 8D 3D ?? ?? ?? ??    // lea r15, key_string
            49 8? ??                // mov rcx, r15
            E8 ?? ?? ?? ??          // call rc4_init
            33 ??                   // xor reg, reg (zero out)
        }

        // PE64 (x64): Base64+RC4 decrypt call pair -> the data
        $data_64 = {
            48 8D 0D ?? ?? ?? ??    // lea rcx, ciphertext_b64
            [0-20]
            E8 ?? ?? ?? ??          // call base64_decode
            [0-20]
            48 8D 15 ?? ?? ?? ??    // lea rdx, ciphertext_b64
            48 ?? ?? ??             // lea rcx, [rbp+output]
            E8 ?? ?? ?? ??          // call rc4_decrypt
        }

    condition:
        uint16(0) == 0x5A4D         // MZ header
        and filesize < 5MB
        and (($key_64 and $data_64) or ($key_32 and $data_32))
        and (all of ($m*) or 1 of ($s*))
}
