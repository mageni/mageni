###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_huawei_switches_multiple_vulnerabilities.nasl 12045 2018-10-24 06:51:17Z mmartin $
#
# Huawei Switches Multiple Vulnerabilities (sa-20171227-01-h323)
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
  script_oid("1.3.6.1.4.1.25623.1.0.113194");
  script_version("$Revision: 12045 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 08:51:17 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-05-23 12:57:41 +0200 (Wed, 23 May 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17251", "CVE-2017-17252", "CVE-2017-17253", "CVE-2017-17254", "CVE-2017-17255", "CVE-2017-17256", "CVE-2017-17257", "CVE-2017-17258");

  script_name("Huawei Switches Multiple Vulnerabilities (sa-20171227-01-h323)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_huawei_switch_detect.nasl");
  script_mandatory_keys("huawei_switch/detected", "huawei_switch/model", "huawei_switch/version");

  script_tag(name:"summary", value:"Huawei Switches are prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The vulnerabilities exist due to:

  - Null pointer dereference

  - Out-of-Bounds read

  - Memory Leak

  - Resource Management vulnerability

  An attacker could send malformed packages to exploit these vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation could crash processes or render the product temporarily inaccessible.");
  script_tag(name:"affected", value:"Following products and firmware versions are affected:

  - AR120-S / AR1200-S / AR200-S / AR2200-S / SRG3300: V200R006C10, V200R007C00, V200R008C20, V200R008C30

  - SRG1300 / SRG2300: V200R006C10, V200R007C00, V200R007C02, V200R008C20, V200R008C30

  - AR150-S: V200R006C10SPC300, V200R007C00, V200R008C20, V200R008C30

  - AR200: V200R006C10, V200R007C00, V200R007C01, V200R008C20, V200R008C30

  - AR1200: V200R006C10, V200R006C13, V200R007C00, V200R007C01, V200R007C02, V200R008C20, V200R008C30

  - AR150: V200R006C10, V200R007C00, V200R007C01, V200R007C02, V200R008C20, V200R008C30

  - AR160: V200R006C10, V200R006C12, V200R007C00, V200R007C01, V200R007C02, V200R008C20, V200R008C30

  - AR2200: V200R006C10, V200R006C13, V200R006C16PWE, V200R007C00, V200R007C01, V200R007C02, V200R008C20, V200R008C30

  - AR3200: V200R006C10, V200R006C11, V200R007C00, V200R007C01, V200R007C02, V200R008C00, V200R008C10, V200R008C20, V200R008C30

  - AR3600: V200R006C10, V200R007C00, V200R007C01, V200R008C20

  - AR510: V200R006C10, V200R006C12, V200R006C13, V200R006C15, V200R006C16, V200R006C17, V200R007C00SPC180T, V200R008C20, V200R008C30

  - DP300: V500R002C00, IPS Module V100R001C10SPC200, V100R001C20, V100R001C30, V500R001C00, V500R001C20, V500R001C30, V500R001C50

  - NGFW Module: V100R001C10SPC200, V100R001C20, V100R001C30, V500R001C00, V500R001C20, V500R002C00, V500R002C10

  - NIP6300 / NIP6600:  V500R001C00, V500R001C20, V500R001C30, V500R001C50

  - NIP6800: V500R001C50

  - NetEngine16EX: V200R006C10, V200R007C00, V200R008C20, V200R008C30

  - RSE6500 V500R002C00

  - SVN5600 / SVN5800 / SVN5800-C: V200R003C00, V200R003C10

  - SeMG9811 V300R001C01

  - Secospace USG6300 / Secospace USG6500: V100R001C10, V100R001C20, V100R001C30, V500R001C00, V500R001C20, V500R001C30, V500R001C50

  - Secospace USG6600 V100R001C00SPC200, V100R001C10, V100R001C20, V100R001C30, V500R001C00, V500R001C20, V500R001C30, V500R001C50, V500R001C60

  - TE30 V100R001C02, V100R001C10, V500R002C00, V600R006C00

  - TE40 / TE50: V500R002C00, V600R006C00

  - TE60 V100R001C01, V100R001C10, V500R002C00, V600R006C00

  - TP3106 V100R002C00

  - TP3206 V100R002C00, V100R002C10

  - USG6000V V500R001C20

  - USG9500 V500R001C00, V500R001C20, V500R001C30, V500R001C50

  - USG9520 V300R001C01, V300R001C20, USG9560 V300R001C01, V300R001C20

  - USG9580 V300R001C01, V300R001C20

  - VP9660 V500R002C00, V500R002C10

  - ViewPoint 8660 V100R008C03

  - ViewPoint 9030 V100R011C02");
  script_tag(name:"solution", value:"Following device/firmware combinations contain a fix:

  - AR120-S / AR1200 / AR1200-S / AR150 / AR150-S / AR160 / AR200 / AR200-S / AR2200 / AR2200-S / AR3200 / AR3600 / AR510 / NetEngine16EX / SRG1300 / SRG2300 / SRG3300 : V200R009C00

  - DP300 / RSE6500: V500R002C00SPCb00

  - IPS Module / NGFW Module / NIP6300 / NIP6600 / NIP6800: V500R001C60SPC500

  - SVN5600 / SVN5800 / SVN5800-C: V200R003C10SPCa00

  - SeMG9811: V500R002C20SPC500

  - Secospace USG6300 / Secospace USG6500 / Secospace USG6600: V500R001C60SPC500

  - TE30 / TE40 / TE50 / TE60: V600R006C00SPC500

  - TP3106: V100R002C00

  - TP3206: V100R002C00SPC800

  - USG6000V: V500R003C00

  - USG9500 / USG9520 / USG9560 / USG9580: V500R001C60SPC500

  - VP9660: V500R002C10SPCb00

  - ViewPoint 8660: V100R008C03SPCe00

  - ViewPoint 9030: V100R011C03SPC900");

  script_xref(name:"URL", value:"http://www.huawei.com/en/psirt/security-advisories/huawei-sa-20171227-01-h323-en");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );
include( "revisions-lib.inc" );

if( ! model = get_kb_item( "huawei_switch/model" ) ) exit( 0 );
if( ! version = get_kb_item( "huawei_switch/version" ) ) exit( 0 );

if( ( model =~ '^AR[0-9]{3,4}(-S)?' || model =~ '^SRG[123]300' || model =~ 'NetEngine16EX' ) && revcomp( a: version, b: "v200r009c00" ) < 0) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V200R009C00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( ( model =~ 'DP300' || model =~ 'RSE6500' ) && revcomp( a: version, b: "v500r002c00spcb00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R002C00SPCb00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( ( model =~ 'IPS Module' || model =~ 'NGFW Module' || model =~ 'NIP6[368]00' ) && revcomp( a: version, b: "v500r001c60spc500" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R001C60SPC500" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '^SVN5[68]00(-C)?' && revcomp( a: version, b: "v200r003c10spca00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V200R003C10SPCa00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ 'SeMG9811' && revcomp( a: version, b: "v500r002c20spc500" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R002C20SPC500" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ 'USG6[356]00' && revcomp( a: version, b: "v500r001c60spc500" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R001C60SPC500" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '^TE[3456]0' && revcomp( a: version, b: "v600r006c00spc500" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V600R006C00SPC500" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '^TP3106' && revcomp( a: version, b: "v100r002c00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V100R002C00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '^TP3206' && revcomp( a: version, b: "v100r002c00spc800" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V100R002C00SPC800" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ 'USG6000V' && revcomp( a: version, b: "v500r003c00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R003C00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ 'USG95[0268]0' && revcomp( a: version, b: "v500r001c60spc500" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R001C60SPC500" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '(VP|VP |ViewPoint )9660' && revcomp( a: version, b: "v500r002c10spcb00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V500R002C10SPCb00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '(VP|VP |ViewPoint )8660' && revcomp( a: version, b: "v100r008c03spce00" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V100R008C04SPCe00" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( model =~ '(VP|VP |ViewPoint )9030' && revcomp( a: version, b: "v100r011c03spc900" ) < 0 ) {
  report = report_fixed_ver( installed_version: toupper( version ), fixed_version: "V100R011C03SPC900" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
