###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xr_cisco-sa-20160525-ipv6.nasl 12431 2018-11-20 09:21:00Z asteins $
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

CPE = "cpe:/o:cisco:ios_xr";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105736");
  script_cve_id("CVE-2016-1409");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12431 $");

  script_name("Cisco Products IPv6 Neighbor Discovery Crafted Packet Denial of Service Vulnerability");

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

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-30 11:07:17 +0200 (Mon, 30 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_ios_xr_version.nasl");
  script_mandatory_keys("cisco/ios_xr/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'2.0.0',
		'3.0.0',
		'3.0.1',
		'3.2.0',
		'3.2.1',
		'3.2.2',
		'3.2.3',
		'3.2.4',
		'3.2.50',
		'3.2.6',
		'3.3.0',
		'3.3.1',
		'3.3.2',
		'3.3.3',
		'3.3.4',
		'3.4.0',
		'3.4.1',
		'3.4.2',
		'3.4.3',
		'3.5.0',
		'3.5.2',
		'3.5.3',
		'3.5.4',
		'3.6 Base',
		'3.6.1',
		'3.6.2',
		'3.6.3',
		'3.6.0',
		'3.7 Base',
		'3.7.1',
		'3.7.2',
		'3.7.3',
		'3.7.0',
		'3.8.0',
		'3.8.1',
		'3.8.2',
		'3.8.3',
		'3.8.4',
		'3.9.0',
		'3.9.1',
		'3.9.2',
		'3.9.3',
		'4.0 Base',
		'4.0.0',
		'4.0.1',
		'4.0.2',
		'4.0.3',
		'4.0.4',
		'4.0.11',
		'4.1 Base',
		'4.1.0',
		'4.1.1',
		'4.1.2',
		'4.2.0',
		'4.2.1',
		'4.2.2',
		'4.2.3',
		'4.2.4',
		'4.3.0',
		'4.3.1',
		'4.3.2',
		'4.3.3',
		'4.3.4',
		'5.1.0',
		'5.1.1',
		'5.1.2',
		'5.1.1.K9SEC',
		'5.1.3',
		'5.2.0',
		'5.2.1',
		'5.2.2',
		'5.2.4',
		'5.2.3',
		'5.2.5',
		'5.3.0',
		'5.3.1',
		'5.3.2',
		'5.0 Base',
		'5.0.0',
		'5.0.1' );

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

