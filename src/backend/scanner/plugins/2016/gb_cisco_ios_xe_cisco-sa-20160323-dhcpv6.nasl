###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20160323-dhcpv6.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco IOS and IOS XE Software DHCPv6 Relay Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105664");
  script_cve_id("CVE-2016-1348");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12313 $");

  script_name("Cisco IOS and IOS XE Software DHCPv6 Relay Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-dhcpv6");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20160323-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the DHCP version 6 (DHCPv6) relay feature of Cisco IOS
  and IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload.

  The vulnerability is due to insufficient validation of DHCPv6 relay messages. An attacker could exploit
  this vulnerability by sending a crafted DHCPv6 relay message to an affected device. A successful exploit
  could allow the attacker to cause the affected device to reload, resulting in a denial of service (DoS) condition.

  Cisco has released software updates that address this vulnerability. There are no workarounds that address this vulnerability.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication,
  which includes six Cisco Security Advisories that describe six vulnerabilities. All the vulnerabilities have a
  Security Impact Rating of `High.` For a complete list of advisories and links to them, see Cisco Event Response:
  Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-09 17:36:49 +0200 (Mon, 09 May 2016)");
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
		'3.8.0E',
		'3.3.0XO',
		'3.3.1XO',
		'3.3.2XO',
		'3.5.0E',
		'3.5.1E',
		'3.5.2E',
		'3.5.3E',
		'3.5.0S',
		'3.5.1S',
		'3.5.2S',
		'3.6.0E',
		'3.6.1E',
		'3.6.2aE',
		'3.6.2E',
		'3.6.3E',
		'3.6.0S',
		'3.6.1S',
		'3.6.2S',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E',
		'3.7.0S',
		'3.7.1S',
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
		'3.10.1S',
		'3.10.1xbS',
		'3.10.2S',
		'3.10.3S',
		'3.10.4S',
		'3.10.5S',
		'3.10.6S',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.11.3S',
		'3.11.4S',
		'3.12.0S',
		'3.12.1S',
		'3.12.4S',
		'3.12.2S',
		'3.12.3S',
		'3.13.2aS',
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
		'3.15.1cS',
		'3.15.0S',
		'3.15.1S',
		'3.15.2S',
		'3.16.0S',
		'3.16.0cS',
		'3.16.1S',
		'3.16.1aS' );

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

