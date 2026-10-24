"""Time zones, countries and languages for a new VM, from Unicode CLDR: windowsZones.xml (typeVersion 2021a,
otherVersion 7e11800) — each Windows time zone with the IANA zones it covers, the main one first, and each zone's
country — and likelySubtags.xml — each country's main language. Made into tables by a one-off script, not edited by
hand.

The app sets a new VM's time zone, regional formats and second keyboard from the time zone of the Proxmox host it runs
on (the user's choice, 24/10, for a project published for everyone: Athens → Greek formats and keyboard), else of this
computer — the first keyboard staying US English, as the console types."""

from __future__ import annotations

import os
import sys

# Windows time zone → its IANA zones, the main one first; "@XX": the zone's country
WINDOWS_ZONES = {
    "AUS Central Standard Time": "Australia/Darwin@AU",
    "AUS Eastern Standard Time": "Australia/Sydney@AU Australia/Melbourne@AU",
    "Afghanistan Standard Time": "Asia/Kabul@AF",
    "Alaskan Standard Time": ("America/Anchorage@US America/Juneau@US America/Metlakatla@US America/Nome@US "
                              "America/Sitka@US America/Yakutat@US"),
    "Alberta Standard Time": "America/Edmonton@CA America/Inuvik@CA",
    "Aleutian Standard Time": "America/Adak@US",
    "Altai Standard Time": "Asia/Barnaul@RU",
    "Arab Standard Time": "Asia/Riyadh@SA Asia/Bahrain@BH Asia/Kuwait@KW Asia/Qatar@QA Asia/Aden@YE",
    "Arabian Standard Time": "Asia/Dubai@AE Asia/Muscat@OM Etc/GMT-4",
    "Arabic Standard Time": "Asia/Baghdad@IQ",
    "Argentina Standard Time": ("America/Buenos_Aires@AR America/Argentina/La_Rioja@AR "
                                "America/Argentina/Rio_Gallegos@AR America/Argentina/Salta@AR "
                                "America/Argentina/San_Juan@AR America/Argentina/San_Luis@AR "
                                "America/Argentina/Tucuman@AR America/Argentina/Ushuaia@AR America/Catamarca@AR "
                                "America/Cordoba@AR America/Jujuy@AR America/Mendoza@AR"),
    "Astrakhan Standard Time": "Europe/Astrakhan@RU Europe/Ulyanovsk@RU",
    "Atlantic Standard Time": ("America/Halifax@CA Atlantic/Bermuda@BM America/Glace_Bay@CA America/Goose_Bay@CA "
                               "America/Moncton@CA America/Thule@GL"),
    "Aus Central W. Standard Time": "Australia/Eucla@AU",
    "Azerbaijan Standard Time": "Asia/Baku@AZ",
    "Azores Standard Time": "Atlantic/Azores@PT America/Scoresbysund@GL",
    "Bahia Standard Time": "America/Bahia@BR",
    "Bangladesh Standard Time": "Asia/Dhaka@BD Asia/Thimphu@BT",
    "Belarus Standard Time": "Europe/Minsk@BY",
    "Bougainville Standard Time": "Pacific/Bougainville@PG",
    "British Columbia Standard Time": "America/Vancouver@CA",
    "Canada Central Standard Time": "America/Regina@CA America/Swift_Current@CA",
    "Cape Verde Standard Time": "Atlantic/Cape_Verde@CV Etc/GMT+1",
    "Caucasus Standard Time": "Asia/Yerevan@AM",
    "Cen. Australia Standard Time": "Australia/Adelaide@AU Australia/Broken_Hill@AU",
    "Central America Standard Time": ("America/Guatemala@GT America/Belize@BZ America/Costa_Rica@CR "
                                      "Pacific/Galapagos@EC America/Tegucigalpa@HN America/Managua@NI "
                                      "America/El_Salvador@SV Etc/GMT+6"),
    "Central Asia Standard Time": "Asia/Bishkek@KG Antarctica/Vostok@AQ Asia/Urumqi@CN Indian/Chagos@IO Etc/GMT-6",
    "Central Brazilian Standard Time": "America/Cuiaba@BR America/Campo_Grande@BR",
    "Central Europe Standard Time": ("Europe/Budapest@HU Europe/Tirane@AL Europe/Prague@CZ Europe/Podgorica@ME "
                                     "Europe/Belgrade@RS Europe/Ljubljana@SI Europe/Bratislava@SK"),
    "Central European Standard Time": "Europe/Warsaw@PL Europe/Sarajevo@BA Europe/Zagreb@HR Europe/Skopje@MK",
    "Central Pacific Standard Time": ("Pacific/Guadalcanal@SB Antarctica/Casey@AQ Pacific/Ponape@FM "
                                      "Pacific/Kosrae@FM Pacific/Noumea@NC Pacific/Efate@VU Etc/GMT-11"),
    "Central Standard Time": ("America/Chicago@US America/Rankin_Inlet@CA America/Resolute@CA "
                              "America/Matamoros@MX America/Ojinaga@MX America/Indiana/Knox@US "
                              "America/Indiana/Tell_City@US America/Menominee@US America/North_Dakota/Beulah@US "
                              "America/North_Dakota/Center@US America/North_Dakota/New_Salem@US"),
    "Central Standard Time (Mexico)": ("America/Mexico_City@MX America/Bahia_Banderas@MX America/Merida@MX "
                                       "America/Monterrey@MX America/Chihuahua@MX"),
    "Chatham Islands Standard Time": "Pacific/Chatham@NZ",
    "China Standard Time": "Asia/Shanghai@CN Asia/Hong_Kong@HK Asia/Macau@MO",
    "Cuba Standard Time": "America/Havana@CU",
    "Dateline Standard Time": "Etc/GMT+12",
    "E. Africa Standard Time": ("Africa/Nairobi@KE Antarctica/Syowa@AQ Africa/Djibouti@DJ Africa/Asmera@ER "
                                "Africa/Addis_Ababa@ET Indian/Comoro@KM Indian/Antananarivo@MG "
                                "Africa/Mogadishu@SO Africa/Dar_es_Salaam@TZ Africa/Kampala@UG Indian/Mayotte@YT "
                                "Etc/GMT-3"),
    "E. Australia Standard Time": "Australia/Brisbane@AU Australia/Lindeman@AU",
    "E. Europe Standard Time": "Europe/Chisinau@MD",
    "E. South America Standard Time": "America/Sao_Paulo@BR",
    "Easter Island Standard Time": "Pacific/Easter@CL",
    "Eastern Standard Time": ("America/New_York@US America/Nassau@BS America/Toronto@CA America/Iqaluit@CA "
                              "America/Detroit@US America/Indiana/Petersburg@US America/Indiana/Vincennes@US "
                              "America/Indiana/Winamac@US America/Kentucky/Monticello@US America/Louisville@US"),
    "Eastern Standard Time (Mexico)": "America/Cancun@MX",
    "Egypt Standard Time": "Africa/Cairo@EG",
    "Ekaterinburg Standard Time": "Asia/Yekaterinburg@RU",
    "FLE Standard Time": ("Europe/Kiev@UA Europe/Mariehamn@AX Europe/Sofia@BG Europe/Tallinn@EE "
                          "Europe/Helsinki@FI Europe/Vilnius@LT Europe/Riga@LV"),
    "Fiji Standard Time": "Pacific/Fiji@FJ",
    "GMT Standard Time": ("Europe/London@GB Atlantic/Canary@ES Atlantic/Faeroe@FO Europe/Guernsey@GG "
                          "Europe/Dublin@IE Europe/Isle_of_Man@IM Europe/Jersey@JE Europe/Lisbon@PT "
                          "Atlantic/Madeira@PT"),
    "GTB Standard Time": "Europe/Bucharest@RO Asia/Nicosia@CY Asia/Famagusta@CY Europe/Athens@GR",
    "Georgian Standard Time": "Asia/Tbilisi@GE",
    "Greenland Standard Time": "America/Godthab@GL",
    "Greenwich Standard Time": ("Atlantic/Reykjavik@IS Africa/Ouagadougou@BF Africa/Abidjan@CI Africa/Accra@GH "
                                "America/Danmarkshavn@GL Africa/Banjul@GM Africa/Conakry@GN Africa/Bissau@GW "
                                "Africa/Monrovia@LR Africa/Bamako@ML Africa/Nouakchott@MR Atlantic/St_Helena@SH "
                                "Africa/Freetown@SL Africa/Dakar@SN Africa/Lome@TG"),
    "Haiti Standard Time": "America/Port-au-Prince@HT",
    "Hawaiian Standard Time": "Pacific/Honolulu@US Pacific/Rarotonga@CK Pacific/Tahiti@PF Etc/GMT+10",
    "India Standard Time": "Asia/Calcutta@IN",
    "Iran Standard Time": "Asia/Tehran@IR",
    "Israel Standard Time": "Asia/Jerusalem@IL",
    "Jordan Standard Time": "Asia/Amman@JO",
    "Kaliningrad Standard Time": "Europe/Kaliningrad@RU",
    "Korea Standard Time": "Asia/Seoul@KR",
    "Libya Standard Time": "Africa/Tripoli@LY",
    "Line Islands Standard Time": "Pacific/Kiritimati@KI Etc/GMT-14",
    "Lord Howe Standard Time": "Australia/Lord_Howe@AU",
    "Magadan Standard Time": "Asia/Magadan@RU",
    "Magallanes Standard Time": "America/Punta_Arenas@CL America/Coyhaique@CL",
    "Manitoba Standard Time": "America/Winnipeg@CA",
    "Marquesas Standard Time": "Pacific/Marquesas@PF",
    "Mauritius Standard Time": "Indian/Mauritius@MU Indian/Reunion@RE Indian/Mahe@SC",
    "Middle East Standard Time": "Asia/Beirut@LB",
    "Montevideo Standard Time": "America/Montevideo@UY",
    "Morocco Standard Time": "Africa/Casablanca@MA Africa/El_Aaiun@EH",
    "Mountain Standard Time": "America/Denver@US America/Cambridge_Bay@CA America/Ciudad_Juarez@MX America/Boise@US",
    "Mountain Standard Time (Mexico)": "America/Mazatlan@MX",
    "Myanmar Standard Time": "Asia/Rangoon@MM Indian/Cocos@CC",
    "N. Central Asia Standard Time": "Asia/Novosibirsk@RU",
    "Namibia Standard Time": "Africa/Windhoek@NA",
    "Nepal Standard Time": "Asia/Katmandu@NP",
    "New Zealand Standard Time": "Pacific/Auckland@NZ Antarctica/McMurdo@AQ",
    "Newfoundland Standard Time": "America/St_Johns@CA",
    "Norfolk Standard Time": "Pacific/Norfolk@NF",
    "North Asia East Standard Time": "Asia/Irkutsk@RU",
    "North Asia Standard Time": "Asia/Krasnoyarsk@RU Asia/Novokuznetsk@RU",
    "North Korea Standard Time": "Asia/Pyongyang@KP",
    "Omsk Standard Time": "Asia/Omsk@RU",
    "Pacific SA Standard Time": "America/Santiago@CL",
    "Pacific Standard Time": "America/Los_Angeles@US",
    "Pacific Standard Time (Mexico)": "America/Tijuana@MX",
    "Pakistan Standard Time": "Asia/Karachi@PK",
    "Paraguay Standard Time": "America/Asuncion@PY",
    "Qyzylorda Standard Time": "Asia/Qyzylorda@KZ",
    "Romance Standard Time": ("Europe/Paris@FR Europe/Brussels@BE Europe/Copenhagen@DK Europe/Madrid@ES "
                              "Africa/Ceuta@ES"),
    "Russia Time Zone 10": "Asia/Srednekolymsk@RU",
    "Russia Time Zone 11": "Asia/Kamchatka@RU Asia/Anadyr@RU",
    "Russia Time Zone 3": "Europe/Samara@RU",
    "Russian Standard Time": "Europe/Moscow@RU Europe/Kirov@RU Europe/Simferopol@UA",
    "SA Eastern Standard Time": ("America/Cayenne@GF Antarctica/Rothera@AQ Antarctica/Palmer@AQ "
                                 "America/Fortaleza@BR America/Belem@BR America/Maceio@BR America/Recife@BR "
                                 "America/Santarem@BR Atlantic/Stanley@FK America/Paramaribo@SR Etc/GMT+3"),
    "SA Pacific Standard Time": ("America/Bogota@CO America/Rio_Branco@BR America/Eirunepe@BR "
                                 "America/Coral_Harbour@CA America/Guayaquil@EC America/Jamaica@JM "
                                 "America/Cayman@KY America/Panama@PA America/Lima@PE Etc/GMT+5"),
    "SA Western Standard Time": ("America/La_Paz@BO America/Antigua@AG America/Anguilla@AI America/Aruba@AW "
                                 "America/Barbados@BB America/St_Barthelemy@BL America/Kralendijk@BQ "
                                 "America/Manaus@BR America/Boa_Vista@BR America/Porto_Velho@BR "
                                 "America/Blanc-Sablon@CA America/Curacao@CW America/Dominica@DM "
                                 "America/Santo_Domingo@DO America/Grenada@GD America/Guadeloupe@GP "
                                 "America/Guyana@GY America/St_Kitts@KN America/St_Lucia@LC America/Marigot@MF "
                                 "America/Martinique@MQ America/Montserrat@MS America/Puerto_Rico@PR "
                                 "America/Lower_Princes@SX America/Port_of_Spain@TT America/St_Vincent@VC "
                                 "America/Tortola@VG America/St_Thomas@VI Etc/GMT+4"),
    "SE Asia Standard Time": ("Asia/Bangkok@TH Antarctica/Davis@AQ Indian/Christmas@CX Asia/Jakarta@ID "
                              "Asia/Pontianak@ID Asia/Phnom_Penh@KH Asia/Vientiane@LA Asia/Saigon@VN Etc/GMT-7"),
    "Saint Pierre Standard Time": "America/Miquelon@PM",
    "Sakhalin Standard Time": "Asia/Sakhalin@RU",
    "Samoa Standard Time": "Pacific/Apia@WS",
    "Sao Tome Standard Time": "Africa/Sao_Tome@ST",
    "Saratov Standard Time": "Europe/Saratov@RU",
    "Singapore Standard Time": ("Asia/Singapore@SG Asia/Brunei@BN Asia/Makassar@ID Asia/Kuala_Lumpur@MY "
                                "Asia/Kuching@MY Asia/Manila@PH Etc/GMT-8"),
    "South Africa Standard Time": ("Africa/Johannesburg@ZA Africa/Bujumbura@BI Africa/Gaborone@BW "
                                   "Africa/Lubumbashi@CD Africa/Maseru@LS Africa/Blantyre@MW Africa/Maputo@MZ "
                                   "Africa/Kigali@RW Africa/Mbabane@SZ Africa/Lusaka@ZM Africa/Harare@ZW "
                                   "Etc/GMT-2"),
    "South Sudan Standard Time": "Africa/Juba@SS",
    "Sri Lanka Standard Time": "Asia/Colombo@LK",
    "Sudan Standard Time": "Africa/Khartoum@SD",
    "Syria Standard Time": "Asia/Damascus@SY",
    "Taipei Standard Time": "Asia/Taipei@TW",
    "Tasmania Standard Time": "Australia/Hobart@AU Antarctica/Macquarie@AU",
    "Tocantins Standard Time": "America/Araguaina@BR",
    "Tokyo Standard Time": "Asia/Tokyo@JP Asia/Jayapura@ID Pacific/Palau@PW Asia/Dili@TL Etc/GMT-9",
    "Tomsk Standard Time": "Asia/Tomsk@RU",
    "Tonga Standard Time": "Pacific/Tongatapu@TO",
    "Transbaikal Standard Time": "Asia/Chita@RU",
    "Turkey Standard Time": "Europe/Istanbul@TR",
    "Turks And Caicos Standard Time": "America/Grand_Turk@TC",
    "US Eastern Standard Time": "America/Indianapolis@US America/Indiana/Marengo@US America/Indiana/Vevay@US",
    "US Mountain Standard Time": ("America/Phoenix@US America/Creston@CA America/Dawson_Creek@CA "
                                  "America/Fort_Nelson@CA America/Hermosillo@MX Etc/GMT+7"),
    "UTC": "Etc/UTC Etc/GMT",
    "UTC+12": ("Etc/GMT-12 Pacific/Tarawa@KI Pacific/Majuro@MH Pacific/Kwajalein@MH Pacific/Nauru@NR "
               "Pacific/Funafuti@TV Pacific/Wake@UM Pacific/Wallis@WF"),
    "UTC+13": "Etc/GMT-13 Pacific/Enderbury@KI Pacific/Fakaofo@TK",
    "UTC-02": "Etc/GMT+2 America/Noronha@BR Atlantic/South_Georgia@GS",
    "UTC-08": "Etc/GMT+8 Pacific/Pitcairn@PN",
    "UTC-09": "Etc/GMT+9 Pacific/Gambier@PF",
    "UTC-11": "Etc/GMT+11 Pacific/Pago_Pago@AS Pacific/Niue@NU Pacific/Midway@UM",
    "Ulaanbaatar Standard Time": "Asia/Ulaanbaatar@MN",
    "Venezuela Standard Time": "America/Caracas@VE",
    "Vladivostok Standard Time": "Asia/Vladivostok@RU Asia/Ust-Nera@RU",
    "Volgograd Standard Time": "Europe/Volgograd@RU",
    "W. Australia Standard Time": "Australia/Perth@AU",
    "W. Central Africa Standard Time": ("Africa/Lagos@NG Africa/Luanda@AO Africa/Porto-Novo@BJ Africa/Kinshasa@CD "
                                        "Africa/Bangui@CF Africa/Brazzaville@CG Africa/Douala@CM "
                                        "Africa/Algiers@DZ Africa/Libreville@GA Africa/Malabo@GQ Africa/Niamey@NE "
                                        "Africa/Ndjamena@TD Africa/Tunis@TN Etc/GMT-1"),
    "W. Europe Standard Time": ("Europe/Berlin@DE Europe/Andorra@AD Europe/Vienna@AT Europe/Zurich@CH "
                                "Europe/Busingen@DE Europe/Gibraltar@GI Europe/Rome@IT Europe/Vaduz@LI "
                                "Europe/Luxembourg@LU Europe/Monaco@MC Europe/Malta@MT Europe/Amsterdam@NL "
                                "Europe/Oslo@NO Europe/Stockholm@SE Arctic/Longyearbyen@SJ Europe/San_Marino@SM "
                                "Europe/Vatican@VA"),
    "W. Mongolia Standard Time": "Asia/Hovd@MN",
    "West Asia Standard Time": ("Asia/Tashkent@UZ Antarctica/Mawson@AQ Asia/Oral@KZ Asia/Almaty@KZ Asia/Aqtau@KZ "
                                "Asia/Aqtobe@KZ Asia/Atyrau@KZ Asia/Qostanay@KZ Indian/Maldives@MV "
                                "Indian/Kerguelen@TF Asia/Dushanbe@TJ Asia/Ashgabat@TM Asia/Samarkand@UZ "
                                "Etc/GMT-5"),
    "West Bank Standard Time": "Asia/Hebron@PS Asia/Gaza@PS",
    "West Pacific Standard Time": ("Pacific/Port_Moresby@PG Antarctica/DumontDUrville@AQ Pacific/Truk@FM "
                                   "Pacific/Guam@GU Pacific/Saipan@MP Etc/GMT-10"),
    "Yakutsk Standard Time": "Asia/Yakutsk@RU Asia/Khandyga@RU",
    "Yukon Standard Time": "America/Whitehorse@CA America/Dawson@CA",
}
# country → its main language (CLDR's likely subtags)
LANGUAGES = {
    "AD": "ca", "AE": "ar", "AF": "fa", "AL": "sq", "AM": "hy", "AO": "pt", "AR": "es", "AS": "sm", "AT": "de",
    "AW": "nl", "AX": "sv", "AZ": "az", "BA": "bs", "BD": "bn", "BE": "nl", "BF": "fr", "BG": "bg", "BH": "ar",
    "BI": "rn", "BJ": "fr", "BL": "fr", "BN": "ms", "BO": "es", "BQ": "pap", "BR": "pt", "BT": "dz", "BY": "ru",
    "CC": "ms", "CD": "fr", "CF": "sg", "CG": "fr", "CH": "de", "CI": "fr", "CL": "es", "CM": "fr", "CN": "zh",
    "CO": "es", "CR": "es", "CU": "es", "CV": "pt", "CW": "pap", "CY": "el", "CZ": "cs", "DE": "de", "DJ": "fr",
    "DK": "da", "DO": "es", "DZ": "ar", "EC": "es", "EE": "et", "EG": "ar", "EH": "ar", "ER": "ti", "ES": "es",
    "ET": "am", "FI": "fi", "FO": "fo", "FR": "fr", "GA": "fr", "GE": "ka", "GF": "fr", "GH": "ak", "GL": "kl",
    "GN": "fr", "GP": "fr", "GQ": "es", "GR": "el", "GT": "es", "GW": "pt", "HK": "zh", "HN": "es", "HR": "hr",
    "HT": "ht", "HU": "hu", "ID": "id", "IL": "he", "IN": "hi", "IQ": "ar", "IR": "fa", "IS": "is", "IT": "it",
    "JO": "ar", "JP": "ja", "KE": "sw", "KG": "ky", "KH": "km", "KM": "ar", "KP": "ko", "KR": "ko", "KW": "ar",
    "KZ": "ru", "LA": "lo", "LB": "ar", "LI": "de", "LK": "si", "LS": "st", "LT": "lt", "LU": "fr", "LV": "lv",
    "LY": "ar", "MA": "ar", "MC": "fr", "MD": "ro", "ME": "sr", "MF": "fr", "MG": "mg", "MK": "mk", "ML": "bm",
    "MM": "my", "MN": "mn", "MO": "zh", "MQ": "fr", "MR": "ar", "MT": "mt", "MU": "fr", "MV": "dv", "MX": "es",
    "MY": "ms", "MZ": "pt", "NA": "af", "NC": "fr", "NE": "ha", "NI": "es", "NL": "nl", "NO": "nb", "NP": "ne",
    "OM": "ar", "PA": "es", "PE": "es", "PF": "fr", "PG": "tpi", "PH": "fil", "PK": "ur", "PL": "pl", "PM": "fr",
    "PR": "es", "PS": "ar", "PT": "pt", "PW": "pau", "PY": "gn", "QA": "ar", "RE": "fr", "RO": "ro", "RS": "sr",
    "RU": "ru", "RW": "rw", "SA": "ar", "SC": "fr", "SD": "ar", "SE": "sv", "SI": "sl", "SJ": "nb", "SK": "sk",
    "SM": "it", "SN": "wo", "SO": "so", "SR": "nl", "SS": "ar", "ST": "pt", "SV": "es", "SY": "ar", "TD": "ar",
    "TF": "fr", "TG": "fr", "TH": "th", "TJ": "tg", "TK": "tkl", "TL": "pt", "TM": "tk", "TN": "ar", "TO": "to",
    "TR": "tr", "TV": "tvl", "TW": "zh", "TZ": "sw", "UA": "uk", "UG": "sw", "UY": "es", "UZ": "uz", "VA": "it",
    "VE": "es", "VN": "vi", "VU": "bi", "WF": "fr", "WS": "sm", "YE": "ar", "YT": "fr", "ZW": "sn",
}
# newer IANA names (tzdata renames) → the name CLDR lists
RENAMED = {"Europe/Kyiv": "Europe/Kiev", "America/Nuuk": "America/Godthab", "Asia/Kolkata": "Asia/Calcutta",
           "Asia/Kathmandu": "Asia/Katmandu", "Asia/Ho_Chi_Minh": "Asia/Saigon", "Asia/Yangon": "Asia/Rangoon",
           "Atlantic/Faroe": "Atlantic/Faeroe", "Pacific/Kanton": "Pacific/Enderbury", "Europe/Uzhgorod": "Europe/Kiev",
           "Europe/Zaporozhye": "Europe/Kiev", "America/Ciudad_Juarez": "America/Ojinaga"}
# keyboard layouts X11 (and so Ubuntu) has by the country's code — most countries; others get none added
XKB_LAYOUTS = set("al am ara at az ba bd be bg br by ca ch cn cz de dk ee es fi fo fr gb ge gh gr hr hu ie il in iq "
                  "ir is it jp ke kg kh kr kz la lk lt lv ma md me mk ml mm mn mt mv my ng nl no np ph pk pl pt ro rs "
                  "ru se si sk sn sy th tj tm tr tw tz ua us uz vn za".split())
_BY_IANA: dict[str, str] = {}
_COUNTRY: dict[str, str] = {}
for _win, _names in WINDOWS_ZONES.items():
    for _entry in _names.split():
        _name, _, _country = _entry.partition("@")
        _BY_IANA.setdefault(_name, _win)
        if _country:
            _COUNTRY.setdefault(_name, _country)


def _known(iana: str) -> str:
    return iana if iana in _BY_IANA else RENAMED.get(iana, iana)


def windows_zone(iana: str) -> str:
    """The Windows name of an IANA zone ("Europe/Athens" → "GTB Standard Time"), or ""."""
    return _BY_IANA.get(_known(iana), "")


def country(iana: str) -> str:
    """The country of an IANA zone ("Europe/Athens" → "GR"), or ""."""
    return _COUNTRY.get(_known(iana), "")


def locale(iana: str) -> str:
    """The language and country of an IANA zone's place ("Europe/Athens" → "el-GR"), or ""."""
    c = country(iana)
    # (CLDR leaves out the countries whose likely language is English: "und" alone is en_Latn_US)
    return f"{LANGUAGES.get(c, 'en')}-{c}" if c and c != "AQ" else ""


def keyboard(iana: str) -> str:
    """The X11 keyboard layout of an IANA zone's country ("Europe/Athens" → "gr"), or ""."""
    c = country(iana).lower()
    return c if c in XKB_LAYOUTS else ""


def local_iana() -> str:
    """This computer's IANA zone (Linux, macOS): $TZ, /etc/timezone, or where /etc/localtime points; "" if unknown."""
    tz = os.environ.get("TZ", "").lstrip(":")
    if tz and "/" in tz and not tz.startswith("/"):
        return tz
    try:
        with open("/etc/timezone", encoding="utf-8") as fh:
            name = fh.read().strip()
            if name:
                return name
    except OSError:
        pass
    try:
        target = os.path.realpath("/etc/localtime")
    except OSError:
        return ""
    marker = "/zoneinfo/"
    return target.split(marker, 1)[1] if marker in target else ""


def windows_zone_here() -> str:
    """This computer's time zone by its Windows name: Windows says it itself; elsewhere from the IANA zone. ""
    when unknown."""
    if sys.platform.startswith("win"):
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation") as key:
                return str(winreg.QueryValueEx(key, "TimeZoneKeyName")[0]).strip("\x00 ")
        except OSError:
            return ""
    return windows_zone(local_iana())


def host_zone(pve, node: str) -> str:
    """The Proxmox node's IANA time zone, or "" if it cannot be read."""
    try:
        return str(pve.node_time(node).get("timezone") or "")
    except Exception:  # (a token without Sys.Audit, an old host: this computer's zone instead)
        return ""


def region(host_zone: str) -> dict:
    """A new VM's place: the Proxmox host's IANA zone (else this computer's) — its Windows name, its country's
    language and country ("el-GR": regional formats, a second keyboard), and X11 keyboard layout."""
    iana = host_zone or local_iana()
    win = windows_zone(iana) or ("" if host_zone else windows_zone_here())
    return {"iana": iana, "windows": win, "locale": locale(iana), "keyboard": keyboard(iana)}
