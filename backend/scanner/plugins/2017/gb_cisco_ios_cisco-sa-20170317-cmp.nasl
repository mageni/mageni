###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20170317-cmp.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IOS Software Cluster Management Protocol Remote Code Execution Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106670");
  script_cve_id("CVE-2017-3881");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco IOS Software Cluster Management Protocol Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170317-cmp");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Cisco Cluster Management Protocol (CMP) processing
code in Cisco IOS Software could allow an unauthenticated, remote attacker to cause a reload of an affected
device or remotely execute code with elevated privileges.");

  script_tag(name:"insight", value:"The Cluster Management Protocol utilizes Telnet internally as a signaling
and command protocol between cluster members. The vulnerability is due to the combination of two factors:

  - The failure to restrict the use of CMP-specific Telnet options only to internal, local communications between
cluster members and instead accept and process such options over any Telnet connection to an affected device, and

  - The incorrect processing of malformed CMP-specific Telnet options.

An attacker could exploit this vulnerability by sending malformed CMP-specific Telnet options while establishing
a Telnet session with an affected Cisco device configured to accept Telnet connections.");

  script_tag(name:"impact", value:"An exploit could allow an attacker to execute arbitrary code and obtain full
control of the device or cause a reload of the affected device.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-20 09:25:26 +0700 (Mon, 20 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version", "cisco_ios/image");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

image = get_kb_item("cisco_ios/image");

if (!image || (image !~ "^C23(5|6)0" && image !~ "^C29(18|28|60|70|75)" && image !~ "^C35(50|60)" &&
    image !~ "^C3750" && image !~ "^C4(0|5)00" && image !~ "^C49(00|28|48)" &&
    image !~ "^WS-CBS30(12|20|30|32|40)" && image !~ "^WS-CBS31(1|2|3)0" && image !~ "^IE(2|3|4|5)000" &&
    image !~ "^IE(3|4)010"))
  exit(99);

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'12.1(11)EA1',
		'12.1(11)EA1a',
		'12.1(12c)EA1',
		'12.1(12c)EA1a',
		'12.1(13)EA1',
		'12.1(13)EA1a',
		'12.1(13)EA1b',
		'12.1(13)EA1c',
		'12.1(14)AZ',
		'12.1(14)EA1',
		'12.1(14)EA1a',
		'12.1(14)EA1b',
		'12.1(19)EA1',
		'12.1(19)EA1a',
		'12.1(19)EA1b',
		'12.1(19)EA1c',
		'12.1(19)EA1d',
		'12.1(20)EA1',
		'12.1(20)EA1a',
		'12.1(20)EA2',
		'12.1(22)EA1',
		'12.1(22)EA10',
		'12.1(22)EA10a',
		'12.1(22)EA10b',
		'12.1(22)EA11',
		'12.1(22)EA12',
		'12.1(22)EA13',
		'12.1(22)EA14',
		'12.1(22)EA1a',
		'12.1(22)EA1b',
		'12.1(22)EA2',
		'12.1(22)EA3',
		'12.1(22)EA4',
		'12.1(22)EA4a',
		'12.1(22)EA5',
		'12.1(22)EA5a',
		'12.1(22)EA6',
		'12.1(22)EA6a',
		'12.1(22)EA7',
		'12.1(22)EA8',
		'12.1(22)EA8a',
		'12.1(22)EA9',
		'12.1(6)EA1',
		'12.1(8)EA1c',
		'12.1(9)EA1',
		'12.2(137)SG',
		'12.2(144)SG',
		'12.2(18)S',
		'12.2(18)SE',
		'12.2(18)SE1',
		'12.2(20)EU',
		'12.2(20)EU1',
		'12.2(20)EU2',
		'12.2(20)EWA',
		'12.2(20)EWA1',
		'12.2(20)EWA2',
		'12.2(20)EWA3',
		'12.2(20)EWA4',
		'12.2(20)EX',
		'12.2(20)SE',
		'12.2(20)SE1',
		'12.2(20)SE2',
		'12.2(20)SE3',
		'12.2(20)SE4',
		'12.2(25)EW',
		'12.2(25)EWA',
		'12.2(25)EWA1',
		'12.2(25)EWA10',
		'12.2(25)EWA11',
		'12.2(25)EWA12',
		'12.2(25)EWA13',
		'12.2(25)EWA14',
		'12.2(25)EWA2',
		'12.2(25)EWA3',
		'12.2(25)EWA4',
		'12.2(25)EWA5',
		'12.2(25)EWA6',
		'12.2(25)EWA7',
		'12.2(25)EWA8',
		'12.2(25)EWA9',
		'12.2(25)EY',
		'12.2(25)EY1',
		'12.2(25)EY2',
		'12.2(25)EY3',
		'12.2(25)EY4',
		'12.2(25)EZ',
		'12.2(25)EZ1',
		'12.2(25)FX',
		'12.2(25)FY',
		'12.2(25)FZ',
		'12.2(25)S',
		'12.2(25)S1',
		'12.2(25)SE',
		'12.2(25)SE1',
		'12.2(25)SE2',
		'12.2(25)SE3',
		'12.2(25)SEA',
		'12.2(25)SEB',
		'12.2(25)SEB1',
		'12.2(25)SEB2',
		'12.2(25)SEB3',
		'12.2(25)SEB4',
		'12.2(25)SEC',
		'12.2(25)SEC1',
		'12.2(25)SEC2',
		'12.2(25)SED',
		'12.2(25)SED1',
		'12.2(25)SEE',
		'12.2(25)SEE1',
		'12.2(25)SEE2',
		'12.2(25)SEE3',
		'12.2(25)SEE4',
		'12.2(25)SEF1',
		'12.2(25)SEF2',
		'12.2(25)SEF3',
		'12.2(25)SEG',
		'12.2(25)SEG1',
		'12.2(25)SEG3',
		'12.2(25)SG',
		'12.2(25)SG1',
		'12.2(25)SG2',
		'12.2(25)SG3',
		'12.2(25)SG4',
		'12.2(31)SG',
		'12.2(31)SG1',
		'12.2(31)SG2',
		'12.2(31)SG3',
		'12.2(31)SGA',
		'12.2(31)SGA1',
		'12.2(31)SGA10',
		'12.2(31)SGA11',
		'12.2(31)SGA2',
		'12.2(31)SGA3',
		'12.2(31)SGA4',
		'12.2(31)SGA5',
		'12.2(31)SGA6',
		'12.2(31)SGA7',
		'12.2(31)SGA8',
		'12.2(31)SGA9',
		'12.2(35)SE',
		'12.2(35)SE1',
		'12.2(35)SE2',
		'12.2(35)SE3',
		'12.2(35)SE5',
		'12.2(37)EY',
		'12.2(37)SE',
		'12.2(37)SE1',
		'12.2(37)SG',
		'12.2(37)SG1',
		'12.2(40)EX',
		'12.2(40)EX1',
		'12.2(40)EX2',
		'12.2(40)EX3',
		'12.2(40)SE',
		'12.2(40)SE1',
		'12.2(40)SE2',
		'12.2(40)SG',
		'12.2(40)XO',
		'12.2(44)EX',
		'12.2(44)EX1',
		'12.2(44)SE',
		'12.2(44)SE1',
		'12.2(44)SE2',
		'12.2(44)SE3',
		'12.2(44)SE4',
		'12.2(44)SE5',
		'12.2(44)SE6',
		'12.2(44)SG',
		'12.2(44)SG1',
		'12.2(44)SQ',
		'12.2(44)SQ2',
		'12.2(46)EX',
		'12.2(46)EY',
		'12.2(46)SE',
		'12.2(46)SE1',
		'12.2(46)SE2',
		'12.2(46)SG',
		'12.2(46)SG1',
		'12.2(50)SE',
		'12.2(50)SE1',
		'12.2(50)SE2',
		'12.2(50)SE3',
		'12.2(50)SE4',
		'12.2(50)SE5',
		'12.2(50)SG',
		'12.2(50)SG1',
		'12.2(50)SG2',
		'12.2(50)SG3',
		'12.2(50)SG4',
		'12.2(50)SG5',
		'12.2(50)SG6',
		'12.2(50)SG7',
		'12.2(50)SG8',
		'12.2(50)SQ',
		'12.2(50)SQ1',
		'12.2(50)SQ2',
		'12.2(50)SQ3',
		'12.2(50)SQ4',
		'12.2(50)SQ5',
		'12.2(50)SQ6',
		'12.2(50)SQ7',
		'12.2(52)EX',
		'12.2(52)EX1',
		'12.2(52)SE',
		'12.2(52)SE1',
		'12.2(52)SG',
		'12.2(52)XO',
		'12.2(53)EY',
		'12.2(53)EZ',
		'12.2(53)SE',
		'12.2(53)SE1',
		'12.2(53)SE2',
		'12.2(53)SG',
		'12.2(53)SG1',
		'12.2(53)SG10',
		'12.2(53)SG11',
		'12.2(53)SG2',
		'12.2(53)SG3',
		'12.2(53)SG4',
		'12.2(53)SG5',
		'12.2(53)SG6',
		'12.2(53)SG7',
		'12.2(53)SG8',
		'12.2(53)SG9',
		'12.2(54)SE',
		'12.2(54)SG',
		'12.2(54)SG1',
		'12.2(54)WO',
		'12.2(54)XO',
		'12.2(55)EX',
		'12.2(55)EX1',
		'12.2(55)EX2',
		'12.2(55)EX3',
		'12.2(55)EY',
		'12.2(55)EZ',
		'12.2(55)SE',
		'12.2(55)SE1',
		'12.2(55)SE10',
		'12.2(55)SE11',
		'12.2(55)SE2',
		'12.2(55)SE3',
		'12.2(55)SE4',
		'12.2(55)SE5',
		'12.2(55)SE6',
		'12.2(55)SE7',
		'12.2(55)SE8',
		'12.2(55)SE9',
		'12.2(58)EX',
		'12.2(58)EZ',
		'12.2(58)SE',
		'12.2(58)SE1',
		'12.2(58)SE2',
		'12.2(60)EZ4',
		'12.2(60)EZ5',
		'15.0(1)EY',
		'15.0(1)EY1',
		'15.0(1)EY2',
		'15.0(1)SE',
		'15.0(1)SE1',
		'15.0(1)SE2',
		'15.0(1)SE3',
		'15.0(1)XO',
		'15.0(1)XO1',
		'15.0(2)EB',
		'15.0(2)EC',
		'15.0(2)ED',
		'15.0(2)EJ',
		'15.0(2)EJ1',
		'15.0(2)EX',
		'15.0(2)EX1',
		'15.0(2)EX10',
		'15.0(2)EX2',
		'15.0(2)EX3',
		'15.0(2)EX4',
		'15.0(2)EX5',
		'15.0(2)EX8',
		'15.0(2)EY',
		'15.0(2)EY1',
		'15.0(2)EY2',
		'15.0(2)EY3',
		'15.0(2)EZ',
		'15.0(2)SE',
		'15.0(2)SE1',
		'15.0(2)SE10',
		'15.0(2)SE10a',
		'15.0(2)SE11',
		'15.0(2)SE2',
		'15.0(2)SE3',
		'15.0(2)SE4',
		'15.0(2)SE5',
		'15.0(2)SE6',
		'15.0(2)SE7',
		'15.0(2)SE8',
		'15.0(2)SE9',
		'15.0(2)SG',
		'15.0(2)SG1',
		'15.0(2)SG10',
		'15.0(2)SG11',
		'15.0(2)SG2',
		'15.0(2)SG3',
		'15.0(2)SG4',
		'15.0(2)SG5',
		'15.0(2)SG6',
		'15.0(2)SG7',
		'15.0(2)SG8',
		'15.0(2)SG9',
		'15.0(2)SQD',
		'15.0(2)SQD1',
		'15.0(2)SQD2',
		'15.0(2)SQD3',
		'15.0(2)SQD4',
		'15.0(2)SQD5',
		'15.0(2)XO',
		'15.0(2a)EX5',
		'15.0(2a)SE9',
		'15.1(1)SG',
		'15.1(1)SG1',
		'15.1(1)SG2',
		'15.1(2)SG',
		'15.1(2)SG1',
		'15.1(2)SG2',
		'15.1(2)SG3',
		'15.1(2)SG4',
		'15.1(2)SG5',
		'15.1(2)SG6',
		'15.1(2)SG7',
		'15.1(2)SG7a',
		'15.1(2)SG8',
		'15.1(2)SG9',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)E2',
		'15.2(1)E3',
		'15.2(1)EY',
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2)E3',
		'15.2(2)E4',
		'15.2(2)E5',
		'15.2(2)E5a',
		'15.2(2)E5b',
		'15.2(2)E6',
		'15.2(2)EB',
		'15.2(2)EB1',
		'15.2(2)EB2',
		'15.2(2a)E1',
		'15.2(2a)E2',
		'15.2(3)E',
		'15.2(3)E1',
		'15.2(3)E2',
		'15.2(3)E3',
		'15.2(3)E4',
		'15.2(3)E5',
		'15.2(3)EX',
		'15.2(3a)E',
		'15.2(3a)E1',
		'15.2(3m)E2',
		'15.2(3m)E3',
		'15.2(3m)E6',
		'15.2(3m)E8',
		'15.2(4)E',
		'15.2(4)E1',
		'15.2(4)E2',
		'15.2(4)E3',
		'15.2(4)EC',
		'15.2(4)EC1',
		'15.2(4)EC2',
		'15.2(4m)E1',
		'15.2(4m)E3',
		'15.2(4n)E2',
		'15.2(4o)E2',
		'15.2(4p)E1',
		'15.2(5)E',
		'15.2(5)E1',
		'15.2(5)EX',
		'15.2(5a)E',
		'15.2(5a)E1',
		'15.2(5b)E',
		'15.2(5c)E' );

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

