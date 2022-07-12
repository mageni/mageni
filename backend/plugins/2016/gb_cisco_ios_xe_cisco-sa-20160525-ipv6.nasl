###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20160525-ipv6.nasl 12338 2018-11-13 14:51:17Z asteins $
#
# Cisco Products IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105735");
  script_cve_id("CVE-2016-1409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12338 $");

  script_name("Cisco Products IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability (IOS XE)");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160525-ipv6");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the IP Version 6 (IPv6) packet processing functions of Cisco IOS XR Software,
  Cisco IOS XE Software, and Cisco NX-OS Software could allow an unauthenticated, remote attacker to
  cause an affected device to stop processing IPv6 traffic, leading to a denial of service (DoS)
  condition on the device.

  The vulnerability is due to insufficient processing logic for crafted IPv6 packets that are sent
  to an affected device. An attacker could exploit this vulnerability by sending crafted IPv6
  Neighbor Discovery packets to an affected device for processing. A successful exploit could allow
  the attacker to cause the device to stop processing IPv6 traffic, leading to a DoS condition on
  the device.

  Cisco will release software updates that address this vulnerability. There are no workarounds that
  address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-30 11:05:22 +0200 (Mon, 30 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xe_version.nasl");
  script_mandatory_keys("cisco_ios_xe/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'16.2.1',
		'16.3.1',
		'16.4.1',
		'3.2.0JA',
		'3.8.0E',
		'3.8.1E',
		'3.8.0EX',
		'99.9.0Z',
		'2.1.0',
		'2.1.1',
		'2.1.2',
		'2.1.3',
		'2.2.0',
		'2.2.1',
		'2.2.2',
		'2.2.3',
		'2.3.1',
		'2.3.0',
		'2.3.0t',
		'2.3.1t',
		'2.3.2',
		'2.4.0',
		'2.4.1',
		'2.4.2',
		'2.4.3',
		'2.5.0',
		'2.5.1',
		'2.5.2',
		'2.6.0',
		'2.6.1',
		'2.6.2',
		'2.6.2a',
		'3.1.3aS',
		'3.1.0S',
		'3.1.1S',
		'3.1.2S',
		'3.1.3S',
		'3.1.4S',
		'3.1.4aS',
		'3.1.5S',
		'3.1.6S',
		'3.1.0SG',
		'3.1.1SG',
		'3.2.0S',
		'3.2.1S',
		'3.2.2S',
		'3.2.3S',
		'3.2.0SE',
		'3.2.1SE',
		'3.2.2SE',
		'3.2.3SE',
		'3.2.0SG',
		'3.2.1SG',
		'3.2.2SG',
		'3.2.3SG',
		'3.2.4SG',
		'3.2.5SG',
		'3.2.6SG',
		'3.2.7SG',
		'3.2.8SG',
		'3.2.9SG',
		'3.2.10SG',
		'3.2.0XO',
		'3.2.1XO',
		'3.3.0S',
		'3.3.1S',
		'3.3.2S',
		'3.3.0SE',
		'3.3.1SE',
		'3.3.2SE',
		'3.3.3SE',
		'3.3.4SE',
		'3.3.5SE',
		'3.3.0SG',
		'3.3.1SG',
		'3.3.2SG',
		'3.3.0SQ',
		'3.3.1SQ',
		'3.3.0XO',
		'3.3.1XO',
		'3.3.2XO',
		'3.4.0S',
		'3.4.0aS',
		'3.4.1S',
		'3.4.2S',
		'3.4.3S',
		'3.4.4S',
		'3.4.5S',
		'3.4.6S',
		'3.4.0SG',
		'3.4.1SG',
		'3.4.2SG',
		'3.4.3SG',
		'3.4.4SG',
		'3.4.5SG',
		'3.4.6SG',
		'3.4.7SG',
		'3.4.0SQ',
		'3.4.1SQ',
		'3.5.0E',
		'3.5.1E',
		'3.5.2E',
		'3.5.3E',
		'3.5.0S',
		'3.5.1S',
		'3.5.2S',
		'3.5.1SQ',
		'3.5.2SQ',
		'3.5.0SQ',
		'3.6.4E',
		'3.6.0E',
		'3.6.1E',
		'3.6.2aE',
		'3.6.2E',
		'3.6.3E',
		'3.6.0S',
		'3.6.1S',
		'3.6.2S',
		'3.7.3E',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E',
		'3.7.0S',
		'3.7.0bS',
		'3.7.0xaS',
		'3.7.1S',
		'3.7.1aS',
		'3.7.2S',
		'3.7.2tS',
		'3.7.3S',
		'3.7.4S',
		'3.7.4aS',
		'3.7.5S',
		'3.7.6S',
		'3.7.7S',
		'3.8.0S',
		'3.8.1S',
		'3.8.2S',
		'3.9.0S',
		'3.9.0aS',
		'3.9.1S',
		'3.9.1aS',
		'3.9.2S',
		'3.10.0S',
		'3.10.0aS',
		'3.10.1S',
		'3.10.1xbS',
		'3.10.2S',
		'3.10.2tS',
		'3.10.3S',
		'3.10.4S',
		'3.10.5S',
		'3.10.6S',
		'3.10.7S',
		'3.10.01S',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.11.3S',
		'3.11.4S',
		'3.12.0S',
		'3.12.0aS',
		'3.12.1S',
		'3.12.4S',
		'3.12.2S',
		'3.12.3S',
		'3.13.2aS',
		'3.13.5S',
		'3.13.0S',
		'3.13.0aS',
		'3.13.1S',
		'3.13.2S',
		'3.13.3S',
		'3.13.4S',
		'3.14.0S',
		'3.14.1S',
		'3.14.2S',
		'3.14.3S',
		'3.14.4S',
		'3.15.1cS',
		'3.15.3S',
		'3.15.0S',
		'3.15.1S',
		'3.15.2S',
		'3.17.0S',
		'3.17.1S',
		'16.1.3',
		'16.1.1',
		'16.1.2',
		'3.16.3S',
		'3.16.0S',
		'3.16.0cS',
		'3.16.1S',
		'3.16.1aS',
		'3.16.2S',
		'3.16.2aS' );

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

