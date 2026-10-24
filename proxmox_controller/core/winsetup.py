"""Windows that installs itself: the answer file (autounattend.xml) Windows Setup looks for on every disc it finds.

The New VM window (and the connector's create_vm) puts it on a small disc of its own next to the Windows ISO. Setup
then needs no keys at all: the VirtIO disk and network drivers load from the VirtIO disc, the disk is partitioned, the
chosen edition is installed, the questions of the first start are skipped, and the user the user named is created
with the password the user typed (in the app's window: Claude never sees it) — signed in once, by itself, so the
last steps run: Remote Desktop, the dark theme, and the VirtIO guest tools (drivers, QEMU guest agent) last — when the
agent answers, Windows is ready and the app takes the answer disc away (core/setupdisc.py).

What Windows asks of an answer file, and what it does with it, is Microsoft's (learn.microsoft.com, "Unattended
Windows Setup Reference"); the passwords in it are only base64 of UTF-16 — Windows' own "hidden" form, not a secret —
so the disc lives on the host only until Windows is ready. Setup copies the file into the new Windows with the
passwords blanked out."""

from __future__ import annotations

import base64
import re
from xml.sax.saxutils import escape

ANSWER_NAME = "autounattend.xml"
DEFAULT_LANGUAGE = "en-US"
EDITIONS = ("Windows 11 Pro", "Windows 11 Home", "Windows 11 Education", "Windows 11 Enterprise",
            "Windows 10 Pro", "Windows 10 Home", "Windows Server 2025 Standard (Desktop Experience)",
            "Windows Server 2022 Standard (Desktop Experience)")
LANGUAGES = ("en-US", "en-GB", "el-GR", "de-DE", "fr-FR", "es-ES", "it-IT", "nl-NL", "pt-PT", "pt-BR", "pl-PL",
             "ru-RU", "tr-TR", "sv-SE", "da-DK", "nb-NO", "fi-FI", "cs-CZ", "hu-HU", "ro-RO", "bg-BG", "uk-UA",
             "ja-JP", "ko-KR", "zh-CN", "zh-TW")
# the language word in Microsoft's ISO names (Win11_25H2_Greek_x64.iso) → the language's code
ISO_LANGUAGE_WORDS = {
    "englishinternational": "en-GB", "english": "en-US", "greek": "el-GR", "german": "de-DE", "frenchcanadian": "fr-CA",
    "french": "fr-FR", "spanish_mexico": "es-MX", "spanish": "es-ES", "italian": "it-IT", "dutch": "nl-NL",
    "brazilianportuguese": "pt-BR", "portuguese": "pt-PT", "polish": "pl-PL", "russian": "ru-RU", "turkish": "tr-TR",
    "swedish": "sv-SE", "danish": "da-DK", "norwegian": "nb-NO", "finnish": "fi-FI", "czech": "cs-CZ",
    "hungarian": "hu-HU", "romanian": "ro-RO", "bulgarian": "bg-BG", "ukrainian": "uk-UA", "japanese": "ja-JP",
    "korean": "ko-KR", "chnsimp": "zh-CN", "chntrad": "zh-TW", "arabic": "ar-SA", "hebrew": "he-IL",
}
US_KEYBOARD = "0409:00000409"  # the console types as a US keyboard: Windows gets that one first
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._ -]{0,19}$")
RESERVED_USERS = ("administrator", "guest", "defaultaccount", "wdagutilityaccount", "system", "none")
LETTERS = "DEFGHIJ"  # where Windows Setup may put the VirtIO disc: each is tried
VIRTIO_DRIVERS = ("vioscsi", "viostor", "NetKVM")  # the disk (SCSI and block) and the network
RDP_FIREWALL_GROUP = "@FirewallAPI.dll,-28752"  # "Remote Desktop", by its resource name: the same in every language
_PS = "powershell -NoProfile -ExecutionPolicy Bypass -Command "


def language_of_iso(volid: str) -> str:
    """The language a Windows ISO installs, from its name: Microsoft's (…_Greek_x64.iso) or a code (…_en-us.iso).
    English (US) when the name does not say."""
    name = volid.rsplit("/", 1)[-1].lower()
    code = re.search(r"(?<![a-z])([a-z]{2})-([a-z]{2})(?![a-z])", name)
    if code:
        return f"{code.group(1)}-{code.group(2).upper()}"
    for word, lang in ISO_LANGUAGE_WORDS.items():  # longest first where one contains another (english…international)
        if re.search(rf"(?:^|[_\-. ]){word}(?:$|[_\-. ])", name):
            return lang
    return DEFAULT_LANGUAGE


def default_edition(profile: str) -> str:
    return "Windows 10 Pro" if profile == "win10" else "Windows 11 Pro"


def has_remote_desktop(edition: str) -> bool:
    """Home has no Remote Desktop server (only the client)."""
    return "home" not in edition.lower()


def is_server(edition: str) -> bool:
    return "server" in edition.lower()


def driver_folder(edition: str) -> str:
    """The VirtIO disc's folder for this Windows (vioscsi\\w11\\amd64…)."""
    e = edition.lower()
    for year, folder in (("2025", "2k25"), ("2022", "2k22"), ("2019", "2k19"), ("2016", "2k16")):
        if "server" in e and year in e:
            return folder
    return "w10" if "windows 10" in e else "w11"


def computer_name(vm_name: str) -> str:
    """Windows' computer name from the VM's: at most 15 letters, digits and hyphens, not only digits; '*' (Windows
    picks one) when nothing is left."""
    name = re.sub(r"[^A-Za-z0-9-]", "-", vm_name.split(".")[0])[:15].strip("-")
    return name if name and not name.isdigit() else "*"


def check_user(user: str, password: str, remote_desktop: bool, edition: str) -> str:
    """What is wrong with these, in words for the user — or ""."""
    if not USERNAME.match(user) or user.strip() != user or user.endswith("."):
        return ("The Windows user name: up to 20 letters, digits, spaces, '.', '-' and '_', starting with a letter or "
                "digit.")
    if user.lower() in RESERVED_USERS:
        return f"'{user}' is one of Windows' own accounts: choose another user name."
    if password and (len(password) > 127 or any(ord(c) < 32 for c in password)):
        return "The password: at most 127 characters, and no control characters."
    if remote_desktop and not password:
        return "Remote Desktop needs a password: Windows refuses remote sign-ins to an account without one."
    if remote_desktop and not has_remote_desktop(edition):
        return "Windows Home has no Remote Desktop server: choose Pro (or Education, Enterprise, Server)."
    if is_server(edition) and not password:
        return "Windows Server needs a password for its Administrator account (the same one is used)."
    return ""


def hidden(password: str, suffix: str) -> str:
    """Windows' "PlainText false" form of a password in an answer file: base64 of UTF-16LE(password + the field's
    name) — Password for a user and for the automatic sign-in, AdministratorPassword for the Administrator."""
    return base64.b64encode((password + suffix).encode("utf-16-le")).decode("ascii")


def _component(name: str, body: str) -> str:
    return (f'    <component name="{name}" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" '
            f'language="neutral" versionScope="nonSxS">\n{body}    </component>\n')


def _locale(lang: str, pe: bool) -> str:
    setup = f"      <SetupUILanguage><UILanguage>{lang}</UILanguage></SetupUILanguage>\n" if pe else ""
    return (f"{setup}      <InputLocale>{US_KEYBOARD}</InputLocale>\n      <SystemLocale>{lang}</SystemLocale>\n"
            f"      <UILanguage>{lang}</UILanguage>\n      <UserLocale>{lang}</UserLocale>\n")


def _disks(uefi: bool) -> tuple[str, int]:
    """The partitions of disk 0 (wiped: it is the new VM's empty disk) and the one Windows goes on."""
    if uefi:  # GPT: EFI system, Microsoft reserved, Windows
        parts = [("EFI", 260, "FAT32", "System", ""), ("MSR", 16, "", "", ""), ("Primary", 0, "NTFS", "Windows", "C")]
    else:  # MBR: system reserved (active), Windows
        parts = [("Primary", 500, "NTFS", "System", ""), ("Primary", 0, "NTFS", "Windows", "C")]
    create, modify = "", ""
    for n, (kind, size, fmt, label, letter) in enumerate(parts, 1):
        extent = "<Extend>true</Extend>" if not size else f"<Size>{size}</Size>"
        create += (f'            <CreatePartition wcm:action="add"><Order>{n}</Order><Type>{kind}</Type>{extent}'
                   "</CreatePartition>\n")
        if fmt:
            extra = "<Active>true</Active>" if not uefi and n == 1 else ""
            extra += f"<Letter>{letter}</Letter>" if letter else ""
            modify += (f'            <ModifyPartition wcm:action="add"><Order>{len(modify.splitlines()) + 1}</Order>'
                       f"<PartitionID>{n}</PartitionID><Format>{fmt}</Format><Label>{label}</Label>{extra}"
                       "</ModifyPartition>\n")
    body = ("      <DiskConfiguration>\n        <Disk wcm:action=\"add\">\n          <DiskID>0</DiskID>\n"
            "          <WillWipeDisk>true</WillWipeDisk>\n          <CreatePartitions>\n" + create +
            "          </CreatePartitions>\n          <ModifyPartitions>\n" + modify +
            "          </ModifyPartitions>\n        </Disk>\n      </DiskConfiguration>\n")
    return body, len(parts)


def first_logon_commands(*, remote_desktop: bool, dark: bool, guest_tools: bool) -> list[tuple[str, str]]:
    """(command line, what it does) run once, in order, at the first sign-in (as the new user, elevated)."""
    out = []
    if remote_desktop:
        out.append((_PS + "\"Set-ItemProperty -Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
                    f"-Name fDenyTSConnections -Value 0; Enable-NetFirewallRule -Group '{RDP_FIREWALL_GROUP}'\"",
                    "Turn on Remote Desktop and let it through the firewall"))
    if dark:
        key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize"
        for value in ("AppsUseLightTheme", "SystemUsesLightTheme"):
            out.append((f"reg add {key} /v {value} /t REG_DWORD /d 0 /f", f"Dark theme ({value})"))
    if guest_tools:  # last: the agent answering is the sign that Windows is ready
        out.append((_PS + "\"Get-PSDrive -PSProvider FileSystem | ForEach-Object { Join-Path $_.Root "
                    "'virtio-win-guest-tools.exe' } | Where-Object { Test-Path $_ } | Select-Object -First 1 | "
                    "ForEach-Object { Start-Process $_ -ArgumentList '/install','/quiet','/norestart' -Wait }\"",
                    "Install the VirtIO guest tools: drivers and the QEMU guest agent"))
    return out


def answer_file(*, user: str, password: str, computer: str, edition: str, uefi: bool, language: str = DEFAULT_LANGUAGE,
                virtio: bool = True, remote_desktop: bool = False, dark: bool = False,
                guest_tools: bool = True, time_zone: str = "") -> str:
    """autounattend.xml for a new VM. `uefi`: the VM boots UEFI (GPT disk) or BIOS (MBR); `virtio`: the VirtIO disc
    is attached (drivers loaded from it in Setup, and its guest tools installed at the end when `guest_tools`).
    `time_zone`: Windows' name of it ("GTB Standard Time") — the app gives this computer's (core/timezones.py); without
    one Windows keeps Pacific time (the first live test showed 10:38 AM at 20:38 in Athens)."""
    problem = check_user(user, password, remote_desktop, edition)
    if problem:
        raise ValueError(problem)
    if language not in LANGUAGES and not re.fullmatch(r"[a-z]{2,3}-[A-Z]{2}", language):
        raise ValueError(f"language {language!r}")
    pe = _component("Microsoft-Windows-International-Core-WinPE", _locale(language, True))
    if virtio:
        paths, n = "", 0
        for letter in LETTERS:
            for driver in VIRTIO_DRIVERS:
                n += 1
                paths += (f'        <PathAndCredentials wcm:action="add" wcm:keyValue="{n}"><Path>{letter}:\\{driver}\\'
                          f"{driver_folder(edition)}\\amd64</Path></PathAndCredentials>\n")
        pe += _component("Microsoft-Windows-PnpCustomizationsWinPE",
                         f"      <DriverPaths>\n{paths}      </DriverPaths>\n")
    disks, windows_part = _disks(uefi)
    pe += _component("Microsoft-Windows-Setup", disks +
                     "      <ImageInstall>\n        <OSImage>\n          <InstallFrom>\n"
                     '            <MetaData wcm:action="add"><Key>/IMAGE/NAME</Key>'
                     f"<Value>{escape(edition)}</Value></MetaData>\n          </InstallFrom>\n"
                     f"          <InstallTo><DiskID>0</DiskID><PartitionID>{windows_part}</PartitionID></InstallTo>\n"
                     "        </OSImage>\n      </ImageInstall>\n"
                     "      <UserData>\n        <ProductKey><WillShowUI>OnError</WillShowUI></ProductKey>\n"
                     "        <AcceptEula>true</AcceptEula>\n      </UserData>\n")
    specialize = _component("Microsoft-Windows-Shell-Setup", f"      <ComputerName>{escape(computer)}</ComputerName>\n")
    secret = f"<Value>{hidden(password, 'Password')}</Value><PlainText>false</PlainText>"
    admin = (f"        <AdministratorPassword><Value>{hidden(password, 'AdministratorPassword')}</Value>"
             "<PlainText>false</PlainText></AdministratorPassword>\n") if is_server(edition) else ""
    commands = "".join(
        f'        <SynchronousCommand wcm:action="add"><Order>{n}</Order><CommandLine>{escape(line)}</CommandLine>'
        f"<Description>{escape(words)}</Description></SynchronousCommand>\n"
        for n, (line, words) in enumerate(first_logon_commands(remote_desktop=remote_desktop, dark=dark,
                                                                guest_tools=guest_tools and virtio), 1))
    shell = ("      <OOBE>\n        <HideEULAPage>true</HideEULAPage>\n"
             "        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>\n"
             "        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>\n"
             "        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>\n"
             "        <HideLocalAccountScreen>true</HideLocalAccountScreen>\n"
             "        <ProtectYourPC>3</ProtectYourPC>\n      </OOBE>\n"
             + (f"      <TimeZone>{escape(time_zone)}</TimeZone>\n" if time_zone else "") +
             "      <UserAccounts>\n" + admin + "        <LocalAccounts>\n"
             '          <LocalAccount wcm:action="add"><Name>' + escape(user) + "</Name><DisplayName>" + escape(user) +
             f"</DisplayName><Group>Administrators</Group><Password>{secret}</Password></LocalAccount>\n"
             "        </LocalAccounts>\n      </UserAccounts>\n"
             f"      <AutoLogon><Enabled>true</Enabled><LogonCount>1</LogonCount><Username>{escape(user)}</Username>"
             f"<Password>{secret}</Password></AutoLogon>\n"
             + (f"      <FirstLogonCommands>\n{commands}      </FirstLogonCommands>\n" if commands else ""))
    oobe = _component("Microsoft-Windows-International-Core", _locale(language, False)) + \
        _component("Microsoft-Windows-Shell-Setup", shell)
    return ('<?xml version="1.0" encoding="utf-8"?>\n'
            '<unattend xmlns="urn:schemas-microsoft-com:unattend" '
            'xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">\n'
            f'  <settings pass="windowsPE">\n{pe}  </settings>\n'
            f'  <settings pass="specialize">\n{specialize}  </settings>\n'
            f'  <settings pass="oobeSystem">\n{oobe}  </settings>\n'
            "</unattend>\n")
