###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20170320-aniipv6.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Cisco IOS Software IPv6 Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106673");
  script_cve_id("CVE-2017-3850");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12106 $");

  script_name("Cisco IOS Software IPv6 Denial of Service Vulnerability");

  script_xref(name:"URL", value:"https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-aniipv6");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A vulnerability in the Autonomic Networking Infrastructure (ANI) feature of
Cisco IOS Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS)
condition.");

  script_tag(name:"insight", value:"The vulnerability is due to incomplete input validation on certain crafted
packets. An attacker could exploit this vulnerability by sending a crafted IPv6 packet to a device that is
running a Cisco IOS Software release that supports the ANI feature.

A device must meet two conditions to be affected by this vulnerability:

  - The device must be running a version of Cisco IOS Software that supports ANI (regardless of whether ANI is
configured)

  - The device must have a reachable IPv6 interface.");

  script_tag(name:"impact", value:"An exploit could allow the attacker to cause the affected device to reload.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-21 09:54:47 +0700 (Tue, 21 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_ssh_cisco_ios_get_version.nasl");
  script_mandatory_keys("cisco_ios/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
		'15.2(3)E',
		'15.2(3)E1',
		'15.2(3)E2',
		'15.2(3)E3',
		'15.2(4)E',
		'15.2(4)E1',
		'15.2(4)E2',
		'15.2(5)E',
		'15.2(5b)E',
		'15.3(3)S',
		'15.3(3)S1',
		'15.3(3)S2',
		'15.3(3)S3',
		'15.3(3)S4',
		'15.3(3)S5',
		'15.3(3)S6',
		'15.4(1)S',
		'15.4(1)S1',
		'15.4(1)S2',
		'15.4(1)S3',
		'15.4(1)S4',
		'15.4(2)S1',
		'15.4(2)S2',
		'15.4(2)S3',
		'15.4(2)S4',
		'15.4(3)S',
		'15.4(3)S1',
		'15.4(3)S2',
		'15.4(3)S3',
		'15.4(3)S4',
		'15.4(3)S5',
		'15.4(3)S6',
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
		'15.5(3)S3',
		'15.5(3)SN',
		'15.6(1)S',
		'15.6(1)S1',
		'15.6(1)S2',
		'15.6(1)T',
		'15.6(1)T0a',
		'15.6(1)T1',
		'15.6(1)T2',
		'15.6(2)S',
		'15.6(2)S1',
		'15.6(2)SN',
		'15.6(2)T',
		'15.6(2)T1',
		'15.6(2)T2',
		'15.6(3)M' );

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

