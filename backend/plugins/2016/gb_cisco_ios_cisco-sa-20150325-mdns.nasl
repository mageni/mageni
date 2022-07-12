###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20150325-mdns.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Cisco IOS Software and IOS XE Software mDNS Gateway Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105643");
  script_cve_id("CVE-2015-0650");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12051 $");

  script_name("Cisco IOS Software and IOS XE Software mDNS Gateway Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-mdns");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAMBAlert.x?alertId=37485");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=37820");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=43609");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150325-bundle");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_mar15.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the multicast DNS (mDNS) gateway function of Cisco
  IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to reload the vulnerable device.

  The vulnerability is due to improper validation of mDNS packets. An attacker could exploit this vulnerability
  by sending malformed IP version 4 (IPv4) or IP version 6 (IPv6) packets on UDP port 5353. An exploit could allow the attacker to cause a denial of service (DoS) condition.

  Cisco has released software updates that address this vulnerability.

  Note: The March 25, 2015, Cisco IOS & XE Software Security Advisory bundled publication includes seven Cisco Security Advisories.
  The advisories address vulnerabilities in Cisco IOS Software and Cisco IOS XE Software. Individual publication links are in Cisco Event Response:
  Semiannual Cisco IOS & XE Software Security Advisory Bundled Publication at the referenced links.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 19:40:36 +0200 (Tue, 03 May 2016)");
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
		'12.2(33)IRD1',
		'12.2(33)IRE3',
		'12.2(44)SQ1',
		'12.2(33)SXI4b',
		'12.4(25e)JAM1',
		'12.4(25e)JAP1m',
		'12.4(25e)JAZ1',
		'15.0(2)ED1',
		'15.1(2)SY',
		'15.1(2)SY1',
		'15.1(2)SY2',
		'15.1(2)SY3',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)E2',
		'15.2(1)E3',
		'15.2(2)E',
		'15.2(1)EX',
		'15.2(2)JB1',
		'15.3(3)JA1n',
		'15.3(3)JAB1',
		'15.3(3)JN',
		'15.3(3)JNB',
		'15.3(2)S2',
		'15.3(3)S',
		'15.3(3)S1',
		'15.3(3)S1a',
		'15.3(3)S2',
		'15.3(3)S3',
		'15.4(3)M',
		'15.4(3)M1',
		'15.4(3)M2',
		'15.4(1)S',
		'15.4(1)S1',
		'15.4(1)S2',
		'15.4(2)S',
		'15.4(2)S1',
		'15.4(3)S',
		'15.4(1)T',
		'15.4(1)T1',
		'15.4(1)T2',
		'15.4(2)T',
		'15.4(2)T1' );

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

