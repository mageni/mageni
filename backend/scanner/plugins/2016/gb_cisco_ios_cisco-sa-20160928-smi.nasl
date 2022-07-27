###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20160928-smi.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco IOS Software Smart Install Memory Leak Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.106314");
  script_cve_id("CVE-2016-6385");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12313 $");

  script_name("Cisco IOS Software Smart Install Memory Leak Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-smi");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The Smart Install client feature in Cisco IOS Software contains a
vulnerability that could allow an unauthenticated, remote attacker to cause a memory leak and eventual denial
of service (DoS) condition on an affected device.");

  script_tag(name:"insight", value:"The vulnerability is due to incorrect handling of image list parameters.
An attacker could exploit this vulnerability by sending crafted Smart Install packets to TCP port 4786.");

  script_tag(name:"impact", value:"A successful exploit could cause the device to leak memory and eventually
reload, resulting in a DoS condition.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 15:42:34 +0700 (Thu, 29 Sep 2016)");
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
		'12.2(35)EX',
		'12.2(35)EX1',
		'12.2(35)EX2',
		'12.2(37)EX',
		'12.2(40)EX',
		'12.2(40)EX1',
		'12.2(40)EX2',
		'12.2(40)EX3',
		'12.2(44)EX',
		'12.2(44)EX1',
		'12.2(46)EX',
		'12.2(52)EX',
		'12.2(52)EX1',
		'12.2(53)EX',
		'12.2(55)EX',
		'12.2(55)EX1',
		'12.2(55)EX2',
		'12.2(55)EX3',
		'12.2(58)EX',
		'12.2(37)EY',
		'12.2(44)EY',
		'12.2(46)EY',
		'12.2(53)EY',
		'12.2(55)EY',
		'12.2(58)EY',
		'12.2(58)EY1',
		'12.2(58)EY2',
		'12.2(53)EZ',
		'12.2(55)EZ',
		'12.2(58)EZ',
		'12.2(60)EZ',
		'12.2(60)EZ1',
		'12.2(60)EZ2',
		'12.2(60)EZ3',
		'12.2(60)EZ4',
		'12.2(60)EZ5',
		'12.2(60)EZ6',
		'12.2(60)EZ7',
		'12.2(60)EZ8',
		'12.2(35)SE',
		'12.2(35)SE1',
		'12.2(35)SE2',
		'12.2(35)SE3',
		'12.2(35)SE4',
		'12.2(35)SE5',
		'12.2(37)SE',
		'12.2(37)SE1',
		'12.2(40)SE',
		'12.2(40)SE1',
		'12.2(40)SE2',
		'12.2(44)SE',
		'12.2(44)SE1',
		'12.2(44)SE2',
		'12.2(44)SE3',
		'12.2(44)SE4',
		'12.2(44)SE5',
		'12.2(44)SE6',
		'12.2(46)SE',
		'12.2(46)SE1',
		'12.2(46)SE2',
		'12.2(50)SE',
		'12.2(50)SE1',
		'12.2(50)SE2',
		'12.2(50)SE3',
		'12.2(50)SE4',
		'12.2(50)SE5',
		'12.2(52)SE',
		'12.2(52)SE1',
		'12.2(53)SE',
		'12.2(53)SE1',
		'12.2(53)SE2',
		'12.2(54)SE',
		'12.2(55)SE',
		'12.2(55)SE1',
		'12.2(55)SE10',
		'12.2(55)SE2',
		'12.2(55)SE3',
		'12.2(55)SE4',
		'12.2(55)SE5',
		'12.2(55)SE6',
		'12.2(55)SE7',
		'12.2(55)SE8',
		'12.2(55)SE9',
		'12.2(58)SE',
		'12.2(58)SE1',
		'12.2(58)SE2',
		'15.0(2)EB',
		'15.0(2)EC',
		'15.0(2)ED',
		'15.0(2)ED1',
		'15.0(2)EH',
		'15.0(2)EJ',
		'15.0(2)EJ1',
		'15.0(2)EK',
		'15.0(2)EK1',
		'15.0(1)EX',
		'15.0(2)EX',
		'15.0(2)EX1',
		'15.0(2)EX10',
		'15.0(2)EX2',
		'15.0(2)EX3',
		'15.0(2)EX4',
		'15.0(2)EX5',
		'15.0(2)EX8',
		'15.0(2a)EX5',
		'15.0(1)EY',
		'15.0(1)EY1',
		'15.0(1)EY2',
		'15.0(2)EY',
		'15.0(2)EY1',
		'15.0(2)EY2',
		'15.0(2)EY3',
		'15.0(2)EZ',
		'15.0(1)SE',
		'15.0(1)SE1',
		'15.0(1)SE2',
		'15.0(1)SE3',
		'15.0(2)SE',
		'15.0(2)SE1',
		'15.0(2)SE2',
		'15.0(2)SE3',
		'15.0(2)SE4',
		'15.0(2)SE5',
		'15.0(2)SE6',
		'15.0(2)SE7',
		'15.0(2)SE9',
		'15.0(2a)SE9',
		'15.1(2)SG',
		'15.1(2)SG1',
		'15.1(2)SG2',
		'15.1(2)SG3',
		'15.1(2)SG4',
		'15.1(2)SG5',
		'15.1(2)SG6',
		'15.1(2)SG7',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)E2',
		'15.2(1)E3',
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2)E4',
		'15.2(2a)E1',
		'15.2(3)E',
		'15.2(3)E1',
		'15.2(3)E2',
		'15.2(3)E3',
		'15.2(3a)E',
		'15.2(3m)E2',
		'15.2(3m)E3',
		'15.2(4)E',
		'15.2(4)E1',
		'15.2(4m)E1',
		'15.2(2)EB',
		'15.2(2)EB1',
		'15.2(2)EB2',
		'15.2(1)EY' );

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

