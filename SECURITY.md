# Security

CardPass is a hobby project with no independent audit. Please report problems privately through the
repository's **Security** tab ("Report a vulnerability"), not in a public issue.

Useful to include: the firmware build id (bottom-right of the splash screen), the Cardputer model, and what an
attacker would need (the unlocked device, the SD card, a USB host, a Bluetooth neighbour).

Known limits: the Cardputer has no secure element, flash encryption and Secure Boot are deliberately off (so launchers
and M5Burner keep working), and Wi-Fi passwords saved for the clock sync are stored unencrypted in the device's NVS.
