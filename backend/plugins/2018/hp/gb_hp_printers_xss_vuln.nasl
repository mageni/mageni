###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printers_xss_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# HP Printers XSS Vulnerability
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.113096");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-30 11:50:00 +0100 (Tue, 30 Jan 2018)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2743");

  script_name("HP Printers XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"HP has identified a potential security vulnerability with certain HP printers. The vulnerability could be exploited to perform a cross site scripting (XSS) attack.");
  script_tag(name:"vuldetect", value:"The script if the target is vulnerable device running a vulnerable firmware version.");
  script_tag(name:"affected", value:"Following devices and firmware versions are affected:

  Firmware versions through 2308214_000900: HP Color LaserJet CM4540 MFP

  Firmware versions through 2308214_000899: HP Color LaserJet CP5525

  Firmware versions through 2308214_000903: HP LaserJet Enterprise M4555 MFP

  Firmware versions through 2308214_000925: HP LaserJet Enterprise 600 M601, HP LaserJet Enterprise 600 M602, HP LaserJet Enterprise 600 M603xh

  Firmware versions through 2308214_000926: HP LaserJet Enterprise Color 500 M551 Series

  Firmware versions through 2308214_000902: HP Scanjet Enterprise 8500 Document Capture Workstation

  Firmware versions through 2308214_000924: HP LaserJet Enterprise 500 color MFP M575dn, HP LaserJet Enterprise color flow MFP M575c

  Firmware versions through 2308214_000912: HP LaserJet Enterprise 500 MFP M525f, HP LaserJet Enterprise flow MFP M525c

  Firmware versions through 2308214_000931: HP LaserJet Enterprise 700 color MFP M775 series

  Firmware versions through 2308214_000921: HP LaserJet Enterprise 700 M712xh

  Firmware versions through 2308214_000920: HP LaserJet Enterprise MFP M725

  Firmware versions through 2308214_000930: HP Color LaserJet Enterprise M750

  Firmware versions through 2308214_000929: HP LaserJet Enterprise 800 color M855

  Firmware versions through 2308214_000927: HP LaserJet Enterprise 800 color MFP M880

  Firmware versions through 2308214_000915: HP LaserJet Enterprise flow M830z MFP

  Firmware versions through 2308214_000919: HP LaserJet Enterprise M806

  Firmware versions through 2308124_000928: HP Color LaserJet Enterprise M651

  Firmware versions through 2308214_000914: HP Color LaserJet M680

  Firmware versions through 2308214_000901: HP OfficeJet Enterprise Color MFP X585

  Firmware versions through 2308214_000905: HP OfficeJet Enterprise Color X555

  Firmware versions through 2308214_000911: HP LaserJet Enterprise MFP M630, HP LaserJet Enterprise Flow MFP M630z

  Firmware versions through 2308214_000906: HP Color LaserJet Enterprise M552, HP Color LaserJet Enterprise M553

  Firmware versions through 2308214_000907: HP LaserJet Enterprise M604, HP LaserJet Enterprise M605, HP LaserJet Enterprise M606

  Firmware versions through 2308214_000908: HP Color LaserJet Enterprise MFP M577

  Firmware versions through 2308214_000910: HP LaserJet Enterprise M506

  Firmware versions through 2308214_000904: HP LaserJet Enterprise M527

  Firmware versions through 2308214_000909: HP PageWide Enterprise Color X556

  Firmware versions through 2308214_000922: HP PageWide Enterprise Color MFP X586");
  script_tag(name:"solution", value:"Following fixed versions exist:

  Firmware version 2308214_000901 and above: HP Color LaserJet CM4540 MFP

  Firmware version 2308214_000900 and above: HP Color LaserJet CP5525

  Firmware version 2308214_000904 and above: HP LaserJet Enterprise M4555 MFP

  Firmware version 2308214_000926 and above: HP LaserJet Enterprise 600 M601, HP LaserJet Enterprise 600 M602, HP LaserJet Enterprise 600 M603xh

  Firmware version 2308214_000927 and above: HP LaserJet Enterprise Color 500 M551 Series

  Firmware version 2308214_000903 and above: HP Scanjet Enterprise 8500 Document Capture Workstation

  Firmware version 2308214_000925 and above: HP LaserJet Enterprise 500 color MFP M575dn, HP LaserJet Enterprise color flow MFP M575c

  Firmware version 2308214_000913 and above: HP LaserJet Enterprise 500 MFP M525f, HP LaserJet Enterprise flow MFP M525c

  Firmware version 2308214_000932 and above: HP LaserJet Enterprise 700 color MFP M775 series

  Firmware version 2308214_000922: and above HP LaserJet Enterprise 700 M712xh

  Firmware version 2308214_000921 and above: HP LaserJet Enterprise MFP M725

  Firmware version 2308214_000931 and above: HP Color LaserJet Enterprise M750

  Firmware version 2308214_000930 and above: HP LaserJet Enterprise 800 color M855

  Firmware version 2308214_000928 and above: HP LaserJet Enterprise 800 color MFP M880

  Firmware version 2308214_000916 and above: HP LaserJet Enterprise flow M830z MFP

  Firmware version 2308214_000920 and above: HP LaserJet Enterprise M806

  Firmware version 2308124_000929 and above: HP Color LaserJet Enterprise M651

  Firmware version 2308214_000915 and above: HP Color LaserJet M680

  Firmware version 2308214_000902 and above: HP OfficeJet Enterprise Color MFP X585

  Firmware version 2308214_000906 and above: HP OfficeJet Enterprise Color X555

  Firmware version 2308214_000912 and above: HP LaserJet Enterprise MFP M630, HP LaserJet Enterprise Flow MFP M630z

  Firmware version 2308214_000907 and above: HP Color LaserJet Enterprise M552, HP Color LaserJet Enterprise M553

  Firmware version 2308214_000908 and above: HP LaserJet Enterprise M604, HP LaserJet Enterprise M605, HP LaserJet Enterprise M606

  Firmware version 2308214_000909 and above: HP Color LaserJet Enterprise MFP M577

  Firmware version 2308214_000911 and above: HP LaserJet Enterprise M506

  Firmware version 2308214_000905 and above: HP LaserJet Enterprise M527

  Firmware version 2308214_000910 and above: HP PageWide Enterprise Color X556

  Firmware version 2308214_000923 and above: HP PageWide Enterprise Color MFP X586");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05541569");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! model = get_kb_item( "hp_model" ) ) exit( 0 );
if( ! fw_ver = get_kb_item( "hp_fw_ver" ) ) exit( 0 );

if( eregmatch( pattern: "LaserJet CM4540 MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000901" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000904" );
  }
}

if( eregmatch( pattern: "LaserJet CP5525", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000899" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000899" );
  }
}

if( eregmatch( pattern: "LaserJet M4555 MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000904" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000904" );
  }
}

if( eregmatch( pattern: "LaserJet 600 M60[123][xh]{0,2}", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000926" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000926" );
  }
}

if( eregmatch( pattern: "LaserJet 500 color M551", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000927" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000927" );
  }
}

if( eregmatch( pattern: "Scanjet 8500", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000903" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000903" );
  }
}

if( eregmatch( pattern: "LaserJet 500 color MFP M575dn", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet color flow MFP M575c", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000925" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000925" );
  }
}

if( eregmatch( pattern: "LaserJet 500 MFP M525f", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet flow MFP M525c", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000913" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000913" );
  }
}

if( eregmatch( pattern: "LaserJet 700 color MFP M775", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000932" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000932" );
  }
}

if( eregmatch( pattern: "LaserJet 700 M712xh", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000922" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000922" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M725", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000921" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000921" );
  }
}

if( eregmatch( pattern: "LaserJet M750", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000931" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000931" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color M855", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000930" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000930" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color MFP M880", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000928" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000928" );
  }
}

if( eregmatch( pattern: "LaserJet flow M830z MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000916" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000916" );
  }
}

if( eregmatch( pattern: "LaserJet M806", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000920" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000920" );
  }
}

if( eregmatch( pattern: "LaserJet M651", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000929" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000929" );
  }
}

if( eregmatch( pattern: "LaserJet M680", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000915" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000915" );
  }
}

if( eregmatch( pattern: "OfficeJet Color MFP X585", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000902" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000902" );
  }
}

if( eregmatch( pattern: "OfficeJet Color X555", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000906" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000906" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M630[z]{0,1}", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000912" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000912" );
  }
}

if( eregmatch( pattern: "LaserJet M55[23]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000907" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000907" );
  }
}

if( eregmatch( pattern: "LaserJet M60[456]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000908" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000908" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M577", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000909" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000909" );
  }
}

if( eregmatch( pattern: "LaserJet M506", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000911" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000911" );
  }
}

if( eregmatch( pattern: "LaserJet M527", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000905" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000905" );
  }
}

if( eregmatch( pattern: "PageWide color X557", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000910" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000910" );
  }
}

if( eregmatch( pattern: "PageWide color MFP X586", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308214_000923" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308214_000923" );
  }
}

if( ! isnull( report ) ) {
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
