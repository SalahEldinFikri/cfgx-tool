// Key and IV are 16 bytes in .rdata, loaded by two different lea instructions.
// The config blob is length-prefixed in the sample, so skip 4 bytes and read 256.
rule Example_AES {
  meta:
    family      = "ExampleFamily"
    config_size = 256
    config_adjust = 4
    key_size    = 32
    iv_size     = 16
  strings:
    $config = { 48 8D 0D ?? ?? ?? ?? E8 }
    $key    = { 48 8D 15 ?? ?? ?? ?? 41 B8 20 00 00 00 }
    $iv     = { 4C 8D 05 ?? ?? ?? ?? }
  condition:
    all of them
}
