# CardPass user guide

CardPass is an offline KeePass (KDBX 4) password manager for the M5Stack Cardputer ADV.
It opens the same `.kdbx` files as KeePassXC and KeePass 2. Nothing is ever sent anywhere: there is
no cloud, and Wi-Fi is only used to set the clock while no database is open.

## Getting started

1. Put your database on the SD card, in a folder named `cardpass` (files in the card's root are found too).
   Databases must be **KDBX 4** (KeePassXC and KeePass 2 default). Both key derivations work:
   - **AES-KDF**: fast on the Cardputer (it has AES hardware).
   - **Argon2d / Argon2id** (the KeePassXC default): works, but Argon2 is *designed* to need a lot of memory and
     the Cardputer has very little, so the memory goes to an encrypted file on the SD card. That is slow: with
     KeePass' defaults (64 MiB, 10+ iterations) an unlock can take tens of minutes. For a usable unlock, set
     Argon2 to about **16-32 MiB and 2-3 iterations** in KeePassXC (Database Settings -> Security), or switch to
     AES-KDF. The progress screen shows the time left. Older KDBX 3 files are refused with a message.
2. Install the firmware (`dist/CardPass.bin` with an SD launcher such as M5Launcher, or
   `dist/CardPass-full.bin` with M5Burner).
3. Pick the database and type the master password. Press **fn+E** to show or hide what you type (the eye at the
   right end of the field; it is hidden again on every new screen).
   If the database also uses a key file, press **Tab**: a file browser opens in the database folder (folders first,
   `..` or Left goes up, Enter opens a folder or chooses a file; any file on the SD card can be a key file).
   **fn+Backspace** clears the chosen key file.

## Keys

The Cardputer has no arrow keys: `;` `,` `.` `/` are up, left, down, right, and fn + the same key types the
character itself. Settings -> Arrows = "fn + key" swaps that (fn + key = arrow, the key alone types).

| keys | action |
|---|---|
| `;` `,` `.` `/` | up, left, down, right (fn + key types `;` `,` `.` `/`) |
| fn + `` ` `` | Esc |
| `` ` `` (alone) | back |
| fn + Backspace | delete (the selected entry) |
| fn + L | lock now |
| fn + E | show / hide a password while typing (unlock, change password, new database, Wi-Fi) |
| fn + S | save (in the entry editor) |
| Tab | menu |
| ? | key help for the current screen |

## Finding entries

The home screen lists your **favorites** (entries tagged `favorite`, in KeePassXC too), then the
entries you opened this session, then your groups. Just **start typing** to search: case and accents
are ignored (`cafe` finds `Café`), letters may be skipped (`gml` finds `Gmail`), and it looks in the
title, user name, URL and tags. Enter opens, `` ` `` goes back, fn + `` ` `` clears the search.

## An entry

| key | action |
|---|---|
| Enter | **type** the selected field into the computer (USB, or Bluetooth if connected) |
| A | auto-type the whole login (default `{USERNAME}{TAB}{PASSWORD}{ENTER}`, or the entry's own sequence) |
| R or fn + E | reveal the selected password (press to show, press again to hide; Settings -> Reveal can make R a hold) |
| Q | show the selected field as a **QR code** (phones can scan it; any key closes it) |
| F | add / remove from favorites |
| E | edit |
| M | move to another group |
| T | set the time (when the TOTP row says *time not set*) |
| fn + Backspace | delete (goes to the recycle bin if the database has one) |
| Enter on a file row | read a **text attachment** (first 16 KB; other files: open them on the PC) |

The password row shows *Strong / Weak* and an estimate of its strength in bits (an estimate, never
exact). TOTP codes show a countdown; typing a code waits for the next one if less than 3 seconds remain.
Passkeys created in KeePassXC show as *Passkey* rows.

Auto-type understands `{USERNAME} {PASSWORD} {TITLE} {URL} {NOTES} {TOTP} {S:FieldName}`, keys like
`{TAB 2}` `{ENTER}` `{DELAY 500}`, and `{DELAY=20}` for a slower typing speed. If any character cannot
be typed on the chosen keyboard layout, **nothing is typed at all** (you get a message instead of a
half-typed password). Set the host's layout in Settings -> Keyboard (US, UK, FR AZERTY, DE QWERTZ).

## The menu (Tab)

New entry, password generator, password audit (weakest first), expiring entries, settings, lock now,
USB drive, set time, groups, change password, Bluetooth.

- **Generator**: password (length, character sets, no look-alikes, at least one of each) or
  passphrase (EFF word list, 4-10 words, separator, capitals, digit, symbol). The exact strength in
  bits is shown. Enter uses it (while editing) or types it.
- **Groups**: create, rename, move, delete the current group. Deleting goes to the recycle bin.
- **Change password**: asks for the current password again, then sets a new password and optionally a
  new key file, and can change how long unlocking takes. The old `.bak` backup is deleted because it
  would still open with the old password.
- **Look**: the Bio-Resonant UI (IBM Plex Sans, superellipse shapes). Four themes in Settings -> Theme:
  **Dusk** (dark, default), **Deep night** (dark, dimmer: lower text contrast in exchange for less light at night;
  the trade is shown when you pick it), **Daylight** (light), **Sunrise** (light, slightly warmer).
  Text size **Large** uses Bio-Resonant's own size (3 rows); **Normal** fits 5.
- **Settings**: theme, text size, reveal mode, **animations (optional)**, auto-lock, dim and screen-off
  times, keyboard layout, typing speed, time zone, "weak below" threshold, expiry warning, default
  auto-type sequence, and the **splash screen** (the CardPass logo at start-up, about 3 s, any key skips it).

## Typing over USB, Bluetooth, and drive mode

- **USB**: plug the Cardputer into the computer: it is a keyboard ("CardPass") and a FIDO security key.
- **Bluetooth**: Menu -> Bluetooth -> Enter, then pair "CardPass" in the computer's Bluetooth settings.
  Both screens show a 6-digit code: confirm it matches. Bluetooth is **off until you turn it on**, and
  turns itself off after 2 minutes without typing, when you lock, and in drive mode.
- **Passkeys**: passkeys stored in KeePassXC work on sites that offer a security key. When a site asks,
  the Cardputer shows the site and the account: press Enter to approve, `` ` `` to deny.
  (Registering a new passkey is done in KeePassXC.)
- **USB drive**: Menu -> USB drive locks the database and makes the SD card a normal drive on your
  computer, for copying `.kdbx` and key files. Eject it on the computer first, then press `` ` ``.

## The clock

The Cardputer ADV has no clock chip, so **set the time after every power-on** (TOTP codes and expiry
warnings need it). Menu -> Set time: by hand (your local time, using the time zone setting), or over
Wi-Fi (scans networks, remembers up to 4; only available while the database is locked).

## Security in short

- The database stays encrypted on the SD card; passwords are decrypted one at a time, only when shown
  or typed, and wiped right after. Nothing decrypted is ever written to the SD card or flash.
- Locking (fn + L, auto-lock, battery empty, entering drive mode) wipes the keys and all buffers.
- Wi-Fi only runs to set the time, with no database open. Bluetooth only runs when you switch it on,
  and never sends typing over an unauthenticated link.
- There is no brute-force delay and no device PIN: a stolen *locked* device reveals nothing without the
  master password, but anyone holding the device can reflash it. Keep it with you, and keep key files
  on a different card than the database.

## Limits

KDBX 4 only. Argon2 needs free space on the SD card (as much as its memory setting, e.g. 64 MB) and time.
Attachments and custom icons are kept untouched but not
displayed (text attachments can be read). No database merging. Very large databases are limited by the
Cardputer's RAM (roughly 800-1,000 entries; `docs/first-hardware.md` explains how to measure yours).
