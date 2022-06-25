###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20140326-ipv6.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco IOS Software Crafted IPv6 Packet Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105649");
  script_cve_id("CVE-2014-2113");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12096 $");

  script_name("Cisco IOS Software Crafted IPv6 Packet Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ipv6");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20140326-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=33351");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_mar14.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the implementation of the IP version 6 (IPv6) protocol
  stack in Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause
  I/O memory depletion on an affected device that has IPv6 enabled. The vulnerability is triggered when an affected
  device processes a malformed IPv6 packet.

  Cisco has released software updates that address this vulnerability. There are no workarounds to mitigate this vulnerability.

  Note: The March 26, 2014, Cisco IOS Software Security Advisory bundled publication includes six Cisco Security Advisories.
  All advisories address vulnerabilities in Cisco IOS Software. Each Cisco IOS Software Security Advisory lists the Cisco IOS
  Software releases that correct the vulnerability or vulnerabilities detailed in the advisory as well as the Cisco IOS Software
  releases that correct all Cisco IOS Software vulnerabilities in the March 2014 bundled publication.

  Individual publication links are in Cisco Event Response: Semiannual Cisco IOS Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-04 18:48:33 +0200 (Wed, 04 May 2016)");
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
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)EY',
		'15.2(4)GC',
		'15.2(4)JA',
		'15.2(4)JA1',
		'15.2(4)JAY',
		'15.2(4)JB',
		'15.2(4)JB1',
		'15.2(4)JB2',
		'15.2(4)JB3',
		'15.2(4)JB3a',
		'15.2(4)JN',
		'15.2(4)M',
		'15.2(4)M1',
		'15.2(4)M2',
		'15.2(4)M3',
		'15.2(4)M4',
		'15.2(4)M5',
		'15.2(4)S',
		'15.2(4)S0c',
		'15.2(4)S1',
		'15.2(4)S2',
		'15.2(4)S3',
		'15.2(4)S3a',
		'15.2(4)S4',
		'15.2(4)S4a',
		'15.2(4)XB10',
		'15.3(3)M',
		'15.3(3)M1',
		'15.3(1)S',
		'15.3(1)S1',
		'15.3(1)S1e',
		'15.3(1)S2',
		'15.3(2)S',
		'15.3(2)S0a',
		'15.3(2)S0xa',
		'15.3(2)S1',
		'15.3(2)S1b',
		'15.3(2)S1c',
		'15.3(2)S2',
		'15.3(3)S',
		'15.3(3)S0b',
		'15.3(3)S1',
		'15.3(3)S1a',
		'15.3(1)T',
		'15.3(1)T1',
		'15.3(1)T2',
		'15.3(1)T3',
		'15.3(2)T',
		'15.3(2)T1',
		'15.3(2)T2' );

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

