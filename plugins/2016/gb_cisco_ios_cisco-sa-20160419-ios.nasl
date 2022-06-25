###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20160419-ios.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Cisco IOS and Cisco IOS XE ntp Subsystem Unauthorized Access Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/o:cisco:ios";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105631");
  script_cve_id("CVE-2016-1384");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 11922 $");

  script_name("Cisco IOS and Cisco IOS XE ntp Subsystem Unauthorized Access Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160419-ios");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the ntp subsystem of Cisco IOS and Cisco IOS XE Software could allow an unauthenticated, remote attacker to mobilize ntp associations.

The vulnerability is due to missing authorization checks on certain ntp packets. An attacker could exploit this vulnerability by ingressing malicious packets to the ntp daemon. An exploit could allow the attacker to control the time of the affected device.

Cisco has released software updates that address this vulnerability. Workarounds that address this vulnerability are not available.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 17:30:06 +0200 (Tue, 03 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
                '15.0(1)EZ',
		'15.1(1)S',
		'15.1(1)S1',
		'15.1(1)S2',
                '15.1(1)SY',
                '15.1(1)XO',
		'15.1(2)S',
		'15.1(2)S1',
		'15.1(2)S2',
                '15.1(2)SG',
                '15.1(2)SY',
                '15.1(3)MRA',
		'15.1(3)S',
		'15.1(3)S0a',
		'15.1(3)S1',
		'15.1(3)S2',
		'15.1(3)S3',
		'15.1(3)S4',
		'15.1(3)S5',
		'15.1(3)S5a',
		'15.1(3)S6',
                '15.2(1)E',
                '15.2(2)E',
                '15.2(3)E',
                '15.2(3)E1',
                '15.2(3)E2',
                '15.2(3)E3',
                '15.2(3)E4',
                '15.2(4)E',
                '15.2(4)E1',
                '15.2(4)E2',
                '15.2(2)EA',
                '15.2(3)EA',
                '15.2(4)EA',
                '15.2(2)EB',
                '15.2(1)EY',
                '15.2(3)GC',
                '15.2(4)GC',
                '15.2(3)GCA',
                '15.2(4)JA',
                '15.2(4)JAZ',
                '15.2(4)JB',
                '15.2(4)JN',
                '15.2(4)M',
                '15.2(2)S',
                '15.2(4)S',
                '15.2(2)SA',
                '15.2(2)SC',
                '15.2(2)SNG',
                '15.2(2)SNH',
                '15.2(2)SNH1',
                '15.2(2)SNI',
                '15.2(1)SY',
                '15.2(2)SY',
                '15.2(3)T',
                '15.2(3)XA',
                '15.2(4)XB',
                '15.3(3)JA',
                '15.3(3)JAA',
                '15.3(3)JAB',
                '15.3(3)JAX',
                '15.3(3)JB',
                '15.3(3)JBB',
                '15.3(3)JC',
                '15.3(3)JD',
                '15.3(3)JN',
                '15.3(3)JNB1',
                '15.3(3)JNC',
                '15.3(3)JNP',
                '15.3(3)M',
                '15.3(1)S',
                '15.3(2)S',
                '15.3(3)S',
                '15.3(3)S1',
                '15.3(3)S2',
                '15.3(3)S3',
                '15.3(3)S4',
                '15.3(3)S5',
                '15.3(3)S6',
                '15.3(3)S7',
                '15.3(3)S8',
                '15.3(0)SY',
                '15.3(1)SY',
                '15.3(1)T',
                '15.3(2)T',
                '15.3(3)XB12',
                '15.4(1)CG',
                '15.4(2)CG',
                '15.4(3)M',
                '15.4(3)M1',
                '15.4(3)M2',
                '15.4(3)M3',
                '15.4(3)M4',
                '15.4(3)M5',
                '15.4(3)M6',
                '15.4(1)S',
                '15.4(2)S',
                '15.4(3)S',
                '15.4(2)SN',
                '15.4(1)T',
                '15.4(2)T',
		'15.5(3)M',
		'15.5(3)M0a',
		'15.5(3)M1',
		'15.5(3)M2',
		'15.5(1)S',
		'15.5(1)S1',
		'15.5(1)S2',
		'15.5(1)S3',
		'15.5(1)S4',
		'15.5(2)S',
		'15.5(2)S1',
		'15.5(2)S2',
		'15.5(2)S3',
		'15.5(3)S',
		'15.5(3)S0a',
		'15.5(3)S1',
		'15.5(3)S1a',
		'15.5(3)S2',
		'15.5(3)SN',
		'15.5(1)T',
		'15.5(2)T',
                '15.5(2)XB',
                '15.6(1)S',
                '15.6(1)S1',
                '15.6(1)SN',
                '15.6(1)SN1',
                '15.6(1)SN2',
                '15.6(1)T',
                '15.6(2)T' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

