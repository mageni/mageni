###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_printers_dll_validation_flaw.nasl 14159 2019-03-13 14:57:01Z cfischer $
#
# HP Printers Insufficient DLL Signature Validation
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113095");
  script_version("$Revision: 14159 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 15:57:01 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-26 14:20:42 +0100 (Fri, 26 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2750");
  script_bugtraq_id(101965);

  script_name("HP Printers Insufficient DLL Signature Validation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"Multiple HP Printers perform insufficient Solution DLL Signature Validation, allowing for potential execution of arbitrary code.");

  script_tag(name:"vuldetect", value:"The script checks if the target host is a vulnerable device running a vulnerable firmware version.");

  script_tag(name:"impact", value:"Successful exploitation could allow an attacker to gain complete control over the target host.");

  script_tag(name:"affected", value:"HP LaserJet Enterprise, HP PageWide Enterprise, HP LaserJet Managed and HP OfficeJet Enterprise printers. Please see the
  referenced vendor advisory for a full list of affected printers/models and firmware versions.");

  script_tag(name:"solution", value:"The vendor has released firmware updates. Please see the referenced vendor advisory for more information.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05839270");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! model = get_kb_item( "hp_model" ) )
  exit( 0 );

if( ! fw_ver = get_kb_item( "hp_fw_ver" ) )
  exit( 0 );

if( eregmatch( pattern: "LaserJet CM4530 MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578507" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578507" );
  }
}

if( eregmatch( pattern: "LaserJet CP5525", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578508" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578508" );
  }
}

if( eregmatch( pattern: "LaserJet M55[23]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578487" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578487" );
  }
}

if( eregmatch( pattern: "LaserJet M651", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578497" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578497" );
  }
}

if( eregmatch( pattern: "LaserJet M750", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578501" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578501" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M577", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578488" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578488" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M680", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578496" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578496" );
  }
}

if( eregmatch( pattern: "LaserJet 500 color[ flow]{0,5} MFP M575", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578502" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578502" );
  }
}

if( eregmatch( pattern: "LaserJet 500 MFP M525", string: model, icase: TRUE )  || eregmatch( pattern: "LaserJet flow MFP M525", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578493" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578493" );
  }
}

if( eregmatch( pattern: "LaserJet 600 M60[123]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578503" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578503" );
  }
}

if( eregmatch( pattern: "LaserJet 700 color MFP M775", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578505" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578505" );
  }
}

if( eregmatch( pattern: "LaserJet 700 M712", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578504" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578504" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color M855", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578499" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578499" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color MFP M880", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578494" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578494" );
  }
}

if( eregmatch( pattern: "LaserJet 500 color M551", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578506" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578506" );
  }
}

if( eregmatch( pattern: "LaserJet flow M830z MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578495" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578495" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M630", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578479" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578479" );
  }
}

if( eregmatch( pattern: "LaserJet M4555 MFP", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578484" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578484" );
  }
}

if( eregmatch( pattern: "LaserJet M506", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578489" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578489" );
  }
}

if( eregmatch( pattern: "LaserJet M527", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578485" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578485" );
  }
}

if( eregmatch( pattern: "LaserJet M60[456]", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578490" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578490" );
  }
}

if( eregmatch( pattern: "LaserJet M806", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578500" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578500" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M725", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578498" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578498" );
  }
}

if( eregmatch( pattern: "OfficeJet Color[ flow]{0,5} MFP X585", string: model, icase: TRUE )  || eregmatch( pattern: "Digital Sender Flow 8500 fn2", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578483" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578483" );
  }
}

if( eregmatch( pattern: "OfficeJet color X555", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578482" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578482" );
  }
}

if( eregmatch( pattern: "PageWide Color[ flow]{0,5} MFP 586", string: model, icase: TRUE )  || eregmatch( pattern: "PageWide Color[ flow]{0,5} MFP E58650", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578491" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578491" );
  }
}

if( eregmatch( pattern: "PageWide Color X556", string: model, icase: TRUE ) || eregmatch( pattern: "PageWide Color E55650", string: model, icase: TRUE ) ) {
  if( version_is_less( version: fw_ver, test_version: "2308937_578487" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2308937_578487" );
  }
}


# For FutureSmart 4 devices, we have to make sure not to report fixed FutureSmart 3 devices as vulnerable. Thus "version_in_range"
if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M68[12f]{1,2}", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet MFP E675[56]0[dhz]{0,2}", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000036" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000037" );
  }
}

if( eregmatch( pattern: "LaserJet M561", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000046" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000047" );
  }
}

if( eregmatch( pattern: "LaserJet M65[23]", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet E650[56]0", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405130_000067" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405130_000068" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M577", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000037" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000038" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M680", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000041" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000042" );
  }
}

if( eregmatch( pattern: "LaserJet color[ flow]{0,5} MFP M575", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000044" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000045" );
  }
}

if( eregmatch( pattern: "LaserJet 500 MFP M525", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet flow MFP M525", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000047" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000048" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color M855", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000056" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000057" );
  }
}

if( eregmatch( pattern: "LaserJet 800 color MFP M800", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000053" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000054" );
  }
}

if( eregmatch( pattern: "LaserJet flow M830z MFP", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000059" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000060" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M630", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000039" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000040" );
  }
}

if( eregmatch( pattern: "LaserJet[ flow]{0,5} MFP M63[123z]{1,2}", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet[ flow]{0,5} MFP E625[567]5[dhsz]{1,2}", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000040" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000041" );
  }
}

if( eregmatch( pattern: "LaserJet M527", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000038" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000039" );
  }
}

if( eregmatch( pattern: "LaserJet M60[789][d]{0,1}", string: model, icase: TRUE ) || eregmatch( pattern: "LaserJet E600[567]5[dn]{0,2}", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405130_000068" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405130_000069" );
  }
}

if( eregmatch( pattern: "LaserJet M806", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000058" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000059" );
  }
}

if( eregmatch( pattern: "LaserJet MFP M725", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000057" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000058" );
  }
}

if( eregmatch( pattern: "LaserJet color[ flow]{0,5} MFP X585", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000049" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000050" );
  }
}

if( eregmatch( pattern: "PageWide Color 765d", string: model, icase: TRUE ) || eregmatch( pattern: "PageWide Color E55650", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405129_000050" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405129_000051" );
  }
}

if( eregmatch( pattern: "Digital Sender Flow 8500 fn2", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405087_018552" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405087_018553" );
  }
}

if( eregmatch( pattern: "ScanJet Flow N9120", string: model, icase: TRUE ) ) {
  if( version_in_range( version: fw_ver, test_version: "2400000_000000", test_version2: "2405087_018551" ) ) {
    report = report_fixed_ver( installed_version: fw_ver, fixed_version: "2405087_018552" );
  }
}

if( ! isnull( report ) ) {
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );