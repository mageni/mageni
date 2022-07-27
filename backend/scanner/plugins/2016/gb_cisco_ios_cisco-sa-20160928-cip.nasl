###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20160928-cip.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Cisco IOS Software Common Industrial Protocol Request Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106296");
  script_cve_id("CVE-2016-6391");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12363 $");

  script_name("Cisco IOS Software Common Industrial Protocol Request Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-cip");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Common Industrial Protocol (CIP) feature of Cisco
IOS Software could allow an unauthenticated, remote attacker to create a denial of service (DoS) condition.");

  script_tag(name:"insight", value:"The vulnerability is due to a failure to properly process an unusual, but
valid, set of requests to an affected device. An attacker could exploit this vulnerability by submitting a CIP
message request designed to trigger the vulnerability to an affected device.");

  script_tag(name:"impact", value:"An exploit could cause the switch to stop processing traffic, requiring a
restart of the device to regain functionality.");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 13:55:06 +0700 (Thu, 29 Sep 2016)");
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
		'12.2(44)EX',
		'12.2(44)EX1',
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
		'12.2(55)SE',
		'12.2(55)SE10',
		'12.2(55)SE3',
		'12.2(55)SE4',
		'12.2(55)SE5',
		'12.2(55)SE6',
		'12.2(55)SE7',
		'12.2(55)SE8',
		'12.2(55)SE9',
		'12.2(58)SE2',
		'15.0(2)EB',
		'15.0(1)EY',
		'15.0(1)EY1',
		'15.0(1)EY2',
		'15.0(2)EY',
		'15.0(2)EY1',
		'15.0(2)EY2',
		'15.0(2)EY3',
		'15.0(2)SE',
		'15.0(2)SE1',
		'15.0(2)SE2',
		'15.0(2)SE3',
		'15.0(2)SE4',
		'15.0(2)SE5',
		'15.0(2)SE6',
		'15.0(2)SE7',
		'15.0(2)SE9',
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2)E4',
		'15.2(3)EA',
		'15.2(1)EY',
		'15.3(3)JA',
		'15.3(3)JA1',
		'15.3(3)JA1m',
		'15.3(3)JA1n',
		'15.3(3)JA4',
		'15.3(3)JA5',
		'15.3(3)JA7',
		'15.3(3)JA77',
		'15.3(3)JA8',
		'15.3(3)JA9',
		'15.3(3)JAA',
		'15.3(3)JAB',
		'15.3(3)JAX',
		'15.3(3)JAX1',
		'15.3(3)JAX2',
		'15.3(3)JB',
		'15.3(3)JB75',
		'15.3(3)JBB',
		'15.3(3)JBB1',
		'15.3(3)JBB2',
		'15.3(3)JBB4',
		'15.3(3)JBB5',
		'15.3(3)JBB50',
		'15.3(3)JBB6',
		'15.3(3)JBB6a',
		'15.3(3)JBB8',
		'15.3(3)JC',
		'15.3(3)JN3',
		'15.3(3)JN4',
		'15.3(3)JN7',
		'15.3(3)JN8',
		'15.3(3)JNB',
		'15.3(3)JNB1',
		'15.3(3)JNB2',
		'15.3(3)JNB3',
		'15.3(3)JNC',
		'15.3(3)JNC1',
		'15.3(3)JNP',
		'15.3(3)JNP1' );

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

