rule DemoFamily {
  meta:
    config_size = 64
    key_size = 16
  strings:
    $config = { 48 8D 05 ?? ?? ?? ?? 90 }
    $key = "KEY1234567890123"
  condition: all of them
}
