###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_pagewide_officejet_printers_rce_vuln.nasl 12116 2018-10-26 10:01:35Z mmartin $
#
# HP Pagewide and OfficeJet Printers RCE Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.113093");
  script_version("$Revision: 12116 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 12:01:35 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-01-25 14:52:55 +0100 (Thu, 25 Jan 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-2741");

  script_name("HP Pagewide and OfficeJet Printers RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Gain a shell remotely");
  script_dependencies("gb_hp_printer_detect.nasl");
  script_mandatory_keys("hp_printer/installed");

  script_tag(name:"summary", value:"A potential security vulnerability has been identified with HP PageWide Printers and HP OfficeJet Pro Printers. This vulnerability could potentially be exploited to execute arbitrary code.");
  script_tag(name:"vuldetect", value:"The script checks if the target host is a vulnerable device running a vulnerable firmware version.");
  script_tag(name:"impact", value:"Successful exploitation would give an attacker complete control over the target host.");
  script_tag(name:"affected", value:"Affected are following HP devices with a firmware version 1707D or below:

  HP PageWide Managed MFP P57750dw

  HP PageWide Managed P55250 dw

  HP PageWide Pro MFP 577z

  HP PageWide Pro 552dw

  HP PageWide Pro MFP 577dw

  HP PageWide Pro MFP 477dw

  HP PageWide Pro 452dw

  HP PageWide Pro MFP 477dn

  HP PageWide Pro 452dn

  HP PageWide MFP 377dw

  HP PageWide 352dw

  HP OfficeJet Pro 8730 All-in-One Printer

  HP OfficeJet Pro 8740 All-in-One Printer

  HP OfficeJet Pro 8210 Printer

  HP OfficeJet Pro 8216 Printer

  HP OfficeJet Pro 8218 Printer");

  script_tag(name:"solution", value:"Update to firmware version 1708D or above.");

  script_xref(name:"URL", value:"https://support.hp.com/us-en/document/c05462914");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42176/");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! model = get_kb_item( "hp_model" ) ) exit( 0 );
if( ! fw_ver = get_kb_item( "hp_fw_ver" ) ) exit( 0 );

affected = make_list( "PageWide Managed MFP P57750dw", "PageWide Managed P55250 dw", "PageWide Pro MFP 577z",
                      "PageWide Pro 552dw", "PageWide Pro MFP 577dw", "PageWide Pro MFP 477dw",
                      "PageWide Pro 452dw", "PageWide Pro MFP 477dn", "PageWide Pro 452dn",
                      "PageWide MFP 377dw", "PageWide 352dw", "OfficeJet Pro 8730",
                      "OfficeJet Pro 8740", "OfficeJet Pro 8210", "OfficeJet Pro 8216",
                      "OfficeJet Pro 8218" );

foreach test_model( affected ) {
  if( ereg( pattern: test_model, string: model, icase: TRUE ) ) {
    ver = eregmatch( pattern: '[.]([0-9]{4}[A-Z])[.]' , string: fw_ver, icase: TRUE );
    if( ! isnull( ver[1] ) ) {
      version = ver[1];
      if( version_is_less( version: version, test_version: "1708D" ) ) {
        report = report_fixed_ver( installed_version: version, fixed_version: "1708D" );
        security_message( data: report, port: 0 );
      }
      else {
        exit( 99 );
      }
    }
    break;
  }
}

exit( 0 );
