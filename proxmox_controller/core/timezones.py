"""Time zones by their Windows names — for a new Windows VM's answer file, which takes only those — with the IANA
zones (what Linux and macOS name) each one covers, the main one first: Unicode CLDR's windowsZones.xml (typeVersion
2021a, otherVersion 7e11800) made into a table by a one-off script, not edited by hand — plus the newer IANA names
CLDR still lists by their old ones."""

from __future__ import annotations

import os
import sys

WINDOWS_ZONES = {
    "AUS Central Standard Time": "Australia/Darwin",
    "AUS Eastern Standard Time": "Australia/Sydney Australia/Melbourne",
    "Afghanistan Standard Time": "Asia/Kabul",
    "Alaskan Standard Time": ("America/Anchorage America/Juneau America/Metlakatla America/Nome America/Sitka "
                              "America/Yakutat"),
    "Alberta Standard Time": "America/Edmonton America/Inuvik",
    "Aleutian Standard Time": "America/Adak",
    "Altai Standard Time": "Asia/Barnaul",
    "Arab Standard Time": "Asia/Riyadh Asia/Bahrain Asia/Kuwait Asia/Qatar Asia/Aden",
    "Arabian Standard Time": "Asia/Dubai Asia/Muscat Etc/GMT-4",
    "Arabic Standard Time": "Asia/Baghdad",
    "Argentina Standard Time": ("America/Buenos_Aires America/Argentina/La_Rioja America/Argentina/Rio_Gallegos "
                                "America/Argentina/Salta America/Argentina/San_Juan America/Argentina/San_Luis "
                                "America/Argentina/Tucuman America/Argentina/Ushuaia America/Catamarca "
                                "America/Cordoba America/Jujuy America/Mendoza"),
    "Astrakhan Standard Time": "Europe/Astrakhan Europe/Ulyanovsk",
    "Atlantic Standard Time": ("America/Halifax Atlantic/Bermuda America/Glace_Bay America/Goose_Bay "
                               "America/Moncton America/Thule"),
    "Aus Central W. Standard Time": "Australia/Eucla",
    "Azerbaijan Standard Time": "Asia/Baku",
    "Azores Standard Time": "Atlantic/Azores America/Scoresbysund",
    "Bahia Standard Time": "America/Bahia",
    "Bangladesh Standard Time": "Asia/Dhaka Asia/Thimphu",
    "Belarus Standard Time": "Europe/Minsk",
    "Bougainville Standard Time": "Pacific/Bougainville",
    "British Columbia Standard Time": "America/Vancouver",
    "Canada Central Standard Time": "America/Regina America/Swift_Current",
    "Cape Verde Standard Time": "Atlantic/Cape_Verde Etc/GMT+1",
    "Caucasus Standard Time": "Asia/Yerevan",
    "Cen. Australia Standard Time": "Australia/Adelaide Australia/Broken_Hill",
    "Central America Standard Time": ("America/Guatemala America/Belize America/Costa_Rica Pacific/Galapagos "
                                      "America/Tegucigalpa America/Managua America/El_Salvador Etc/GMT+6"),
    "Central Asia Standard Time": "Asia/Bishkek Antarctica/Vostok Asia/Urumqi Indian/Chagos Etc/GMT-6",
    "Central Brazilian Standard Time": "America/Cuiaba America/Campo_Grande",
    "Central Europe Standard Time": ("Europe/Budapest Europe/Tirane Europe/Prague Europe/Podgorica "
                                     "Europe/Belgrade Europe/Ljubljana Europe/Bratislava"),
    "Central European Standard Time": "Europe/Warsaw Europe/Sarajevo Europe/Zagreb Europe/Skopje",
    "Central Pacific Standard Time": ("Pacific/Guadalcanal Antarctica/Casey Pacific/Ponape Pacific/Kosrae "
                                      "Pacific/Noumea Pacific/Efate Etc/GMT-11"),
    "Central Standard Time": ("America/Chicago America/Rankin_Inlet America/Resolute America/Matamoros "
                              "America/Ojinaga America/Indiana/Knox America/Indiana/Tell_City America/Menominee "
                              "America/North_Dakota/Beulah America/North_Dakota/Center "
                              "America/North_Dakota/New_Salem"),
    "Central Standard Time (Mexico)": ("America/Mexico_City America/Bahia_Banderas America/Merida "
                                       "America/Monterrey America/Chihuahua"),
    "Chatham Islands Standard Time": "Pacific/Chatham",
    "China Standard Time": "Asia/Shanghai Asia/Hong_Kong Asia/Macau",
    "Cuba Standard Time": "America/Havana",
    "Dateline Standard Time": "Etc/GMT+12",
    "E. Africa Standard Time": ("Africa/Nairobi Antarctica/Syowa Africa/Djibouti Africa/Asmera Africa/Addis_Ababa "
                                "Indian/Comoro Indian/Antananarivo Africa/Mogadishu Africa/Dar_es_Salaam "
                                "Africa/Kampala Indian/Mayotte Etc/GMT-3"),
    "E. Australia Standard Time": "Australia/Brisbane Australia/Lindeman",
    "E. Europe Standard Time": "Europe/Chisinau",
    "E. South America Standard Time": "America/Sao_Paulo",
    "Easter Island Standard Time": "Pacific/Easter",
    "Eastern Standard Time": ("America/New_York America/Nassau America/Toronto America/Iqaluit America/Detroit "
                              "America/Indiana/Petersburg America/Indiana/Vincennes America/Indiana/Winamac "
                              "America/Kentucky/Monticello America/Louisville"),
    "Eastern Standard Time (Mexico)": "America/Cancun",
    "Egypt Standard Time": "Africa/Cairo",
    "Ekaterinburg Standard Time": "Asia/Yekaterinburg",
    "FLE Standard Time": ("Europe/Kiev Europe/Mariehamn Europe/Sofia Europe/Tallinn Europe/Helsinki "
                          "Europe/Vilnius Europe/Riga"),
    "Fiji Standard Time": "Pacific/Fiji",
    "GMT Standard Time": ("Europe/London Atlantic/Canary Atlantic/Faeroe Europe/Guernsey Europe/Dublin "
                          "Europe/Isle_of_Man Europe/Jersey Europe/Lisbon Atlantic/Madeira"),
    "GTB Standard Time": "Europe/Bucharest Asia/Nicosia Asia/Famagusta Europe/Athens",
    "Georgian Standard Time": "Asia/Tbilisi",
    "Greenland Standard Time": "America/Godthab",
    "Greenwich Standard Time": ("Atlantic/Reykjavik Africa/Ouagadougou Africa/Abidjan Africa/Accra "
                                "America/Danmarkshavn Africa/Banjul Africa/Conakry Africa/Bissau Africa/Monrovia "
                                "Africa/Bamako Africa/Nouakchott Atlantic/St_Helena Africa/Freetown Africa/Dakar "
                                "Africa/Lome"),
    "Haiti Standard Time": "America/Port-au-Prince",
    "Hawaiian Standard Time": "Pacific/Honolulu Pacific/Rarotonga Pacific/Tahiti Etc/GMT+10",
    "India Standard Time": "Asia/Calcutta",
    "Iran Standard Time": "Asia/Tehran",
    "Israel Standard Time": "Asia/Jerusalem",
    "Jordan Standard Time": "Asia/Amman",
    "Kaliningrad Standard Time": "Europe/Kaliningrad",
    "Korea Standard Time": "Asia/Seoul",
    "Libya Standard Time": "Africa/Tripoli",
    "Line Islands Standard Time": "Pacific/Kiritimati Etc/GMT-14",
    "Lord Howe Standard Time": "Australia/Lord_Howe",
    "Magadan Standard Time": "Asia/Magadan",
    "Magallanes Standard Time": "America/Punta_Arenas America/Coyhaique",
    "Manitoba Standard Time": "America/Winnipeg",
    "Marquesas Standard Time": "Pacific/Marquesas",
    "Mauritius Standard Time": "Indian/Mauritius Indian/Reunion Indian/Mahe",
    "Middle East Standard Time": "Asia/Beirut",
    "Montevideo Standard Time": "America/Montevideo",
    "Morocco Standard Time": "Africa/Casablanca Africa/El_Aaiun",
    "Mountain Standard Time": "America/Denver America/Cambridge_Bay America/Ciudad_Juarez America/Boise",
    "Mountain Standard Time (Mexico)": "America/Mazatlan",
    "Myanmar Standard Time": "Asia/Rangoon Indian/Cocos",
    "N. Central Asia Standard Time": "Asia/Novosibirsk",
    "Namibia Standard Time": "Africa/Windhoek",
    "Nepal Standard Time": "Asia/Katmandu",
    "New Zealand Standard Time": "Pacific/Auckland Antarctica/McMurdo",
    "Newfoundland Standard Time": "America/St_Johns",
    "Norfolk Standard Time": "Pacific/Norfolk",
    "North Asia East Standard Time": "Asia/Irkutsk",
    "North Asia Standard Time": "Asia/Krasnoyarsk Asia/Novokuznetsk",
    "North Korea Standard Time": "Asia/Pyongyang",
    "Omsk Standard Time": "Asia/Omsk",
    "Pacific SA Standard Time": "America/Santiago",
    "Pacific Standard Time": "America/Los_Angeles",
    "Pacific Standard Time (Mexico)": "America/Tijuana",
    "Pakistan Standard Time": "Asia/Karachi",
    "Paraguay Standard Time": "America/Asuncion",
    "Qyzylorda Standard Time": "Asia/Qyzylorda",
    "Romance Standard Time": "Europe/Paris Europe/Brussels Europe/Copenhagen Europe/Madrid Africa/Ceuta",
    "Russia Time Zone 10": "Asia/Srednekolymsk",
    "Russia Time Zone 11": "Asia/Kamchatka Asia/Anadyr",
    "Russia Time Zone 3": "Europe/Samara",
    "Russian Standard Time": "Europe/Moscow Europe/Kirov Europe/Simferopol",
    "SA Eastern Standard Time": ("America/Cayenne Antarctica/Rothera Antarctica/Palmer America/Fortaleza "
                                 "America/Belem America/Maceio America/Recife America/Santarem Atlantic/Stanley "
                                 "America/Paramaribo Etc/GMT+3"),
    "SA Pacific Standard Time": ("America/Bogota America/Rio_Branco America/Eirunepe America/Coral_Harbour "
                                 "America/Guayaquil America/Jamaica America/Cayman America/Panama America/Lima "
                                 "Etc/GMT+5"),
    "SA Western Standard Time": ("America/La_Paz America/Antigua America/Anguilla America/Aruba America/Barbados "
                                 "America/St_Barthelemy America/Kralendijk America/Manaus America/Boa_Vista "
                                 "America/Porto_Velho America/Blanc-Sablon America/Curacao America/Dominica "
                                 "America/Santo_Domingo America/Grenada America/Guadeloupe America/Guyana "
                                 "America/St_Kitts America/St_Lucia America/Marigot America/Martinique "
                                 "America/Montserrat America/Puerto_Rico America/Lower_Princes "
                                 "America/Port_of_Spain America/St_Vincent America/Tortola America/St_Thomas "
                                 "Etc/GMT+4"),
    "SE Asia Standard Time": ("Asia/Bangkok Antarctica/Davis Indian/Christmas Asia/Jakarta Asia/Pontianak "
                              "Asia/Phnom_Penh Asia/Vientiane Asia/Saigon Etc/GMT-7"),
    "Saint Pierre Standard Time": "America/Miquelon",
    "Sakhalin Standard Time": "Asia/Sakhalin",
    "Samoa Standard Time": "Pacific/Apia",
    "Sao Tome Standard Time": "Africa/Sao_Tome",
    "Saratov Standard Time": "Europe/Saratov",
    "Singapore Standard Time": ("Asia/Singapore Asia/Brunei Asia/Makassar Asia/Kuala_Lumpur Asia/Kuching "
                                "Asia/Manila Etc/GMT-8"),
    "South Africa Standard Time": ("Africa/Johannesburg Africa/Bujumbura Africa/Gaborone Africa/Lubumbashi "
                                   "Africa/Maseru Africa/Blantyre Africa/Maputo Africa/Kigali Africa/Mbabane "
                                   "Africa/Lusaka Africa/Harare Etc/GMT-2"),
    "South Sudan Standard Time": "Africa/Juba",
    "Sri Lanka Standard Time": "Asia/Colombo",
    "Sudan Standard Time": "Africa/Khartoum",
    "Syria Standard Time": "Asia/Damascus",
    "Taipei Standard Time": "Asia/Taipei",
    "Tasmania Standard Time": "Australia/Hobart Antarctica/Macquarie",
    "Tocantins Standard Time": "America/Araguaina",
    "Tokyo Standard Time": "Asia/Tokyo Asia/Jayapura Pacific/Palau Asia/Dili Etc/GMT-9",
    "Tomsk Standard Time": "Asia/Tomsk",
    "Tonga Standard Time": "Pacific/Tongatapu",
    "Transbaikal Standard Time": "Asia/Chita",
    "Turkey Standard Time": "Europe/Istanbul",
    "Turks And Caicos Standard Time": "America/Grand_Turk",
    "US Eastern Standard Time": "America/Indianapolis America/Indiana/Marengo America/Indiana/Vevay",
    "US Mountain Standard Time": ("America/Phoenix America/Creston America/Dawson_Creek America/Fort_Nelson "
                                  "America/Hermosillo Etc/GMT+7"),
    "UTC": "Etc/UTC Etc/GMT",
    "UTC+12": ("Etc/GMT-12 Pacific/Tarawa Pacific/Majuro Pacific/Kwajalein Pacific/Nauru Pacific/Funafuti "
               "Pacific/Wake Pacific/Wallis"),
    "UTC+13": "Etc/GMT-13 Pacific/Enderbury Pacific/Fakaofo",
    "UTC-02": "Etc/GMT+2 America/Noronha Atlantic/South_Georgia",
    "UTC-08": "Etc/GMT+8 Pacific/Pitcairn",
    "UTC-09": "Etc/GMT+9 Pacific/Gambier",
    "UTC-11": "Etc/GMT+11 Pacific/Pago_Pago Pacific/Niue Pacific/Midway",
    "Ulaanbaatar Standard Time": "Asia/Ulaanbaatar",
    "Venezuela Standard Time": "America/Caracas",
    "Vladivostok Standard Time": "Asia/Vladivostok Asia/Ust-Nera",
    "Volgograd Standard Time": "Europe/Volgograd",
    "W. Australia Standard Time": "Australia/Perth",
    "W. Central Africa Standard Time": ("Africa/Lagos Africa/Luanda Africa/Porto-Novo Africa/Kinshasa "
                                        "Africa/Bangui Africa/Brazzaville Africa/Douala Africa/Algiers "
                                        "Africa/Libreville Africa/Malabo Africa/Niamey Africa/Ndjamena "
                                        "Africa/Tunis Etc/GMT-1"),
    "W. Europe Standard Time": ("Europe/Berlin Europe/Andorra Europe/Vienna Europe/Zurich Europe/Busingen "
                                "Europe/Gibraltar Europe/Rome Europe/Vaduz Europe/Luxembourg Europe/Monaco "
                                "Europe/Malta Europe/Amsterdam Europe/Oslo Europe/Stockholm Arctic/Longyearbyen "
                                "Europe/San_Marino Europe/Vatican"),
    "W. Mongolia Standard Time": "Asia/Hovd",
    "West Asia Standard Time": ("Asia/Tashkent Antarctica/Mawson Asia/Oral Asia/Almaty Asia/Aqtau Asia/Aqtobe "
                                "Asia/Atyrau Asia/Qostanay Indian/Maldives Indian/Kerguelen Asia/Dushanbe "
                                "Asia/Ashgabat Asia/Samarkand Etc/GMT-5"),
    "West Bank Standard Time": "Asia/Hebron Asia/Gaza",
    "West Pacific Standard Time": ("Pacific/Port_Moresby Antarctica/DumontDUrville Pacific/Truk Pacific/Guam "
                                   "Pacific/Saipan Etc/GMT-10"),
    "Yakutsk Standard Time": "Asia/Yakutsk Asia/Khandyga",
    "Yukon Standard Time": "America/Whitehorse America/Dawson",
}
# newer IANA names (tzdata renames) → the name CLDR lists
RENAMED = {"Europe/Kyiv": "Europe/Kiev", "America/Nuuk": "America/Godthab", "Asia/Kolkata": "Asia/Calcutta",
           "Asia/Kathmandu": "Asia/Katmandu", "Asia/Ho_Chi_Minh": "Asia/Saigon", "Asia/Yangon": "Asia/Rangoon",
           "Atlantic/Faroe": "Atlantic/Faeroe", "Pacific/Kanton": "Pacific/Enderbury", "Europe/Uzhgorod": "Europe/Kiev",
           "Europe/Zaporozhye": "Europe/Kiev", "America/Ciudad_Juarez": "America/Ojinaga"}
_BY_IANA = {name: win for win, names in WINDOWS_ZONES.items() for name in names.split()}


def windows_zone(iana: str) -> str:
    """The Windows name of an IANA zone ("Europe/Athens" → "GTB Standard Time"), or ""."""
    return _BY_IANA.get(iana) or _BY_IANA.get(RENAMED.get(iana, ""), "")


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
    when unknown (the new Windows then keeps its own default)."""
    if sys.platform.startswith("win"):
        try:
            import winreg
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation") as key:
                return str(winreg.QueryValueEx(key, "TimeZoneKeyName")[0]).strip("\x00 ")
        except OSError:
            return ""
    return windows_zone(local_iana())
