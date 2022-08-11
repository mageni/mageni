###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printer_rce_vuln.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# HP Printers RCE Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113056");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-23 10:11:12 +0100 (Thu, 23 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2750");

  script_name("HP Printers RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Multiple HP Printers are vulnerable to RCE attacks.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable Firmware is installed on the host.");
  script_tag(name:"insight", value:"A flaw in HP's Digital Signature Validation makes it possible to load malicious DLLs onto an HP printer and use it to execute arbitrary code on the machine.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"Affected are the following Printers and Firmwares:

  - HP Color LaserJet Enterprise M651 (CZ255A, CZ256A, CZ257A, CZ258A) - Firmware before v 2405129_000047

  - HP Color LaserJet Enterprise M652 (J7Z98A, J7Z99A) - Firmware before v 2405130_000068

  - HP Color LaserJet Enterprise M653 (J8A04A, J8A05A, J8A06A) - Firmware before v 2405130_000068

  - HP Color LaserJet Enterprise MFP M577 (B5L46A, B5L47A, B5L48A) - Firmware before v 2405129_000038

  - HP Color LaserJet Enterprise M552 (B5L23A, B5L23V) - Firmware before v 2308903_577315

  - HP Color LaserJet Enterprise M553 (B5L24A, B5L25A, B5L26A, B5L27A, B5L38A) - Firmware before v 2308903_577315

  - HP Color LaserJet M680 (CZ250A, CA251A) - Firmware before v 2405129_000042

  - HP Color LaserJet Managed E65050 (L3U55A) - Firmware before v 2405130_000068

  - HP Color LaserJet Managed E65060 (L3U56A, L3U57A) - Firmware before v 2405130_000068

  - HP LaserJet Enterprise 500 color MFP M575 (CD644A, CD645A) - Firmware before v 2405129_000045

  - HP LaserJet Enterprise 500 MFP M525 (CF116A, CF117A) - Firmware before v 2405129_000048

  - HP LaserJet Enterprise 700 color MFP M775 (CF304A, CC523A, CC524C, CC522A, L3U49A, L3U50A) - Firmware before v 2405129_000061

  - HP LaserJet Enterprise 800 color M855 (A2W77A, A2W78A, A2W79A) - Firmware before v 2405129_000057

  - HP LaserJet Enterprise 800 color MFP M880 (A2W76A, A2W75A, D7P70A, D7P71A) - Firmware before v 2405129_000054

  - HP LaserJet Enterprise color flow MFP M575 (CD646A) - Firmware before v 2405129_000045

  - HP LaserJet Enterprise flow M830z MFP (CF367A) - Firmware before v 2405129_000060

  - HP LaserJet Enterprise flow MFP M525 (CF118A) - Firmware before v 2405129_000048

  - HP LaserJet Enterprise Flow MFP M630 (B3G85A) - Firmware before v 2405129_000040

  - HP LaserJet Enterprise Flow MFP M631 (J8J64A) - Firmware before v 2405129_000041

  - HP LaserJet Enterprise Flow MFP M632 (J8J72A) - Firmware before v 2405129_000041

  - HP LaserJet Enterprise Flow MFP M633 (J8J78A) - Firmware before v 2405129_000041

  - HP LaserJet Enterprise M527 (F2A76A, F2A77A, F2A81A) - Firmware before v 2405129_000039

  - HP LaserJet Enterprise M607 (K0Q14A, K0Q15A) - Firmware before v 2405130_000069

  - HP LaserJet Enterprise M608 (K0Q17A, K0Q18A, M0P32A, K0Q19A) - Firmware before v 2405130_000069

  - HP LaserJet Enterprise M609 (K0Q20A, K0Q21A, K0Q22A) - Firmware before v 2405130_000069

  - HP LaserJet Enterprise M806 (CZ244A, CZ245A) - Firmware before v 2405129_000059

  - HP LaserJet Enterprise MFP M630 (J7X28A) - Firmware before v 2405129_000040

  - HP LaserJet Enterprise MFP M631 (J8J63A, J8J65A) - Firmware before v 2405129_000041

  - HP LaserJet Enterprise MFP M632 (J8J70A, J8J71A) - Firmware before v 2405129_000041

  - HP LaserJet Enterprise MFP M633 (J8J76A) - Firmware before v 2405129_000041

  - HP LaserJet Enterprise MFP M725 (CF066A, CF067A, CF068A, CF069A) - Firmware before v 2405129_000058

  - HP LaserJet Managed E60055 (M0P33A) - Firmware before v 2405130_000069

  - HP LaserJet Managed E60065 (M0P35A, M0P36A) - Firmware before v 2405130_000069

  - HP LaserJet Managed E60075 (M0P39A, M0P40A) - Firmware before v 2405130_000069

  - HP LaserJet Managed Flow MFP E62555 (J8J67A) - Firmware before v 2405129_000041

  - HP LaserJet Managed Flow MFP E62565 (J8J74A, J8J79A) - Firmware before v 2405129_000041

  - HP LaserJet Managed Flow MFP E62575 (J8J80A) - Firmware before v 2405129_000041

  - HP LaserJet Managed MFP E62555 (J8J66A) - Firmware before v 2405129_000041

  - HP LaserJet Managed MFP E62565 (J8J73A) - Firmware before v 2405129_000041

  - HP OfficeJet Enterprise Color Flow MFP X585 (B5L06A, B5L06V, , B5L07A) - Firmware before v 2405129_000050

  - HP OfficeJet Enterprise Color MFP X585 (B5L04A, B5L04V, B5L05A, B5L05V) - Firmware before v 2405129_000050

  - HP PageWide Enterprise Color 765 (J7Z04A) - Firmware before v 2405087_018564

  - HP PageWide Enterprise Color MFP 586 (G1W39A, G1W39V, G1W40A, G1W40V) - Firmware before v 2405129_000066

  - HP PageWide Enterprise Color MPF 780 (J7Z09A, J7Z10A) - Firmware before v 2405087_018548

  - HP PageWide Enterprise Color MPF 785 (J7Z11A, J7Z12A) - Firmware before v 2405087_018548

  - HP PageWide Enterprise Color X556 (G1W46A, G1W46V, G1W47A, G1W47V, L3U44A) - Firmware before v 2405129_000051

  - HP PageWide Managed Color E55650 (L3U44A) - Firmware before v 2405129_000051

  - HP PageWide Managed Color E75160 (J7Z06A) - Firmware before v 2405087_018564

  - HP PageWide Managed Color Flow MFP 586 (G1W41A, G1W41V) - Firmware before v 2405129_000066

  - HP PageWide Managed Color Flow MFP E77650 (J7Z08A, J7Z14A) - Firmware before v 2405087_018548

  - HP PageWide Managed Color Flow MFP E77660 (Z5G77A, J7Z03A, J7Z07A, J7Z05A) - Firmware before v 2405087_018548

  - HP PageWide Managed Color MFP E77650 (J7Z13A, Z5G79A) - Firmware before v 2405087_018548

  - HP ScanJet Enterprise Flow N9120 Doc Flatbed Scanner (L2683A) - Firmware before v 2405087_018552

  - HP Digital Sender Flow 8500 fn2 Doc Capture Workstation (L2762A) - Firmware before v 2405087_018553");
  script_tag(name:"solution", value:"Update to the fixed Firmware version");

  script_xref(name:"URL", value:"https://foxglovesecurity.com/2017/11/20/a-sheep-in-wolfs-clothing-finding-rce-in-hps-printer-fleet/#arbcode");
  script_xref(name:"URL", value:"https://support.hp.com/nz-en/document/c05839270");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! model = get_kb_item( "hp_model" ) ) exit( 0 );
if( ! version = get_kb_item( "hp_fw_ver" ) ) exit( 0 );

# "Enterprise" and "Managed" often is omitted from the Product Name on the Web-Interface, thus the RegEx [A-Za-z ]*

# All models with a fixed 2405129_000041 version
forty_one = make_list( "LaserJet[A-Za-z ]*Flow MFP M631",
                       "LaserJet[A-Za-z ]*Flow MFP M632",
                       "LaserJet[A-Za-z ]*Flow MFP M633",
                       "LaserJet[A-Za-z ]*MFP M631",
                       "LaserJet[A-Za-z ]*MFP M632",
                       "LaserJet[A-Za-z ]*MFP M633",
                       "LaserJet[A-Za-z ]*Flow MFP E62555",
                       "LaserJet[A-Za-z ]*Flow MFP E62565",
                       "LaserJet[A-Za-z ]*Flow MFP E62575",
                       "LaserJet[A-Za-z ]*MFP E62555",
                       "LaserJet[A-Za-z ]*MFP E62565" );

# All models with a fixed 2405129_000047 version
forty_seven = make_list( "Color LaserJet[A-Za-z ]*M651" );

# All models with a fixed 2405130_000068 version
sixty_eight = make_list( "Color LaserJet[A-Za-z ]*M652",
                         "Color LaserJet[A-Za-z ]*M563",
                         "Color LaserJet[A-Za-z ]*E65050",
                         "Color LaserJet[A-Za-z ]*E65060" );

# All models with a fixed 2405129_000038 version
thirty_eight = make_list( "Color LaserJet[A-Za-z ]*MFP M577" );

# All models with a fixed 2308903_577315 version
three_fifteen = make_list( "Color LaserJet[A-Za-z ]*M552",
                           "Color LaserJet[A-Za-z ]*M553" );

# All models with a fixed 2405129_000042 version
forty_two = make_list( "Color LaserJet M680" );

# All models with a fixed 2405129_000045 version
forty_five = make_list( "LaserJet[A-Za-z ]*500 color MFP M575",
                        "LaserJet[A-Za-z ]*color flow MFP M575" );

# All models with a fixed 2405129_000048 version
forty_eight = make_list( "LaserJet[A-Za-z ]*500 MFP M525",
                         "LaserJet[A-Za-z ]*flow MFP M525" );

# All models with a fixed 2405129_000061 version
sixty_one = make_list( "LaserJet[A-Za-z ]*700 color MFP M775" );

# All models with a fixed 2405129_000057 version
fifty_seven = make_list( "LaserJet[A-Za-z ]*800 color M855" );

# All models with a fixed 2405129_000054 version
fifty_four = make_list( "LaserJet[A-Za-z ]*800 color MFP M880" );

# All models with a fixed 2405129_000060 version
sixty = make_list( "LaserJet[A-Za-z ]*flow M830z MFP" );

# All models with a fixed 2405129_000040 version
forty = make_list( "LaserJet[A-Za-z ]*MFP M630",
                   "LaserJet[A-Za-z ]*Flow MFP M630" );

# All models with a fixed 2405129_000039 version
thirty_nine = make_list( "LaserJet[A-Za-z ]*M527" );

# All models with a fixed 2405130_000069 version
sixty_nine = make_list( "LaserJet[A-Za-z ]*M607",
                        "LaserJet[A-Za-z ]*M608",
                        "LaserJet[A-Za-z ]*M609",
                        "LaserJet[A-Za-z ]*E60055",
                        "LaserJet[A-Za-z ]*E60065",
                        "LaserJet[A-Za-z ]*E60075" );

# All models with a fixed 2405129_000059 version
fifty_nine = make_list( "LaserJet[A-Za-z ]*M806" );

# All models with a fixed 2405129_000058 version
fifty_eight = make_list( "LaserJet[A-Za-z ]*MFP M725" );

# All models with a fixed 2405129_000050 version
fifty = make_list( "OfficeJet[A-Za-z ]*Color Flow MFP X585",
                   "OfficeJet[A-Za-z ]*Color MFP X585" );

# All models with a fixed 2405087_018564 version
five_sixty_four = make_list( "PageWide[A-Za-z ]*Color 765",
                             "PageWide[A-Za-z ]*Color E75160" );

# All models with a fixed 2405129_000066 version
sixty_six = make_list( "PageWide[A-Za-z ]*Color MFP 586",
                       "PageWide[A-Za-z ]*Color Flow MFP 586" );

# All models with a fixed 2405087_018548 version
five_forty_eight = make_list( "PageWide[A-Za-z ]*Color MPF 780",
                              "PageWide[A-Za-z ]*Color MPF 785",
                              "PageWide[A-Za-z ]*Color Flow MFP E77650",
                              "PageWide[A-Za-z ]*Color Flow MFP E77660",
                              "PageWide[A-Za-z ]*Color MFP E77650" );

# All models with a fixed 2405129_000051 version
fifty_one = make_list( "PageWide[A-Za-z ]*Color X556",
                       "PageWide[A-Za-z ]*Color E55650" );

# All models with a fixed 2405087_018552 version
five_fifty_two = make_list( "ScanJet[A-Za-z ]*Flow N9120 Doc Flatbed Scanner" );

# All models with a fixed 2405087_018553 version
five_fifty_three = make_list( "Digital Sender Flow 8500 fn2 Doc Capture Workstation" );

function check_vuln_firmware( fixed_version ) {
  local_var fixed_version;

  if( version_is_less( version: version, test_version: fixed_version ) ) {
    report = report_fixed_ver( installed_version: version, fixed_version: fixed_version );
    security_message( data: report, port: 0 );
    exit( 0 );
  }
}


foreach pattern ( forty_one) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000041" );
  }
}

foreach pattern ( forty_seven ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000047" );
  }
}

foreach pattern ( sixty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000068" );
  }
}

foreach pattern ( thirty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000038" );
  }
}

foreach pattern ( three_fifteen ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2308903_577315" );
  }
}

foreach pattern ( forty_two ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000042" );
  }
}

foreach pattern ( forty_five ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000045" );
  }
}

foreach pattern ( forty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000048" );
  }
}

foreach pattern ( sixty_one ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000061" );
  }
}

foreach pattern ( fifty_seven ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000057" );
  }
}

foreach pattern ( fifty_four ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000054" );
  }
}

foreach pattern ( sixty ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000060" );
  }
}

foreach pattern ( forty ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_00040" );
  }
}

foreach pattern ( thirty_nine ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000039" );
  }
}

foreach pattern ( sixty_nine ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405130_000069" );
  }
}

foreach pattern ( fifty_nine ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000059" );
  }
}

foreach pattern ( fifty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000058" );
  }
}

foreach pattern ( fifty ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000050" );
  }
}

foreach pattern ( five_sixty_four ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_18564" );
  }
}

foreach pattern ( sixty_six ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000066" );
  }
}

foreach pattern ( five_forty_eight ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_018548" );
  }
}

foreach pattern ( fifty_one ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405129_000051" );
  }
}

foreach pattern ( five_fifty_two ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_018552" );
  }
}

foreach pattern ( five_fifty_three ) {
  if( eregmatch( pattern: pattern, string: model, icase: TRUE ) ) {
    check_vuln_firmware( fixed_version: "2405087_018223" );
  }
}
