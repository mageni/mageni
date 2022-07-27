###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20120926-ios-ips.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco IOS Software Intrusion Prevention System Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105656");
  script_cve_id("CVE-2012-3950");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12313 $");

  script_name("Cisco IOS Software Intrusion Prevention System Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20120926-bundle");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep12.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"Cisco IOS Software contains a vulnerability in the Intrusion Prevention System (IPS)
feature that could allow an unauthenticated, remote attacker to cause a reload of an affected device if specific Cisco IOS IPS configurations exist.

Cisco has released software updates that address this vulnerability.

Workarounds that mitigate this vulnerability are available.

Note: The September 26, 2012, Cisco IOS Software Security Advisory bundled publication includes nine Cisco Security Advisories.
Eight of the advisories address vulnerabilities in Cisco IOS Software, and one advisory addresses a vulnerability in Cisco Unified Communications Manager.
Each Cisco IOS Software Security Advisory lists the Cisco IOS Software releases that correct the vulnerability or vulnerabilities detailed in the advisory
as well as the Cisco IOS Software releases that correct all Cisco IOS Software vulnerabilities in the September 2012 bundled publication.

Individual publication links are in `Cisco Event Response: Semi-Annual Cisco IOS Software Security Advisory Bundled Publication` at the referenced link.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-06 14:09:55 +0200 (Fri, 06 May 2016)");
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
		'12.4(22)GC1',
		'12.4(22)GC1a',
		'12.4(24)GC1',
		'12.4(24)GC3',
		'12.4(24)GC3a',
		'12.4(24)GC4',
		'12.4(16)MR1',
		'12.4(16)MR2',
		'12.4(19)MR',
		'12.4(11)T',
		'12.4(11)T1',
		'12.4(11)T2',
		'12.4(11)T3',
		'12.4(11)T4',
		'12.4(15)T',
		'12.4(15)T1',
		'12.4(15)T10',
		'12.4(15)T11',
		'12.4(15)T12',
		'12.4(15)T13',
		'12.4(15)T14',
		'12.4(15)T15',
		'12.4(15)T16',
		'12.4(15)T17',
		'12.4(15)T2',
		'12.4(15)T3',
		'12.4(15)T4',
		'12.4(15)T5',
		'12.4(15)T6',
		'12.4(15)T7',
		'12.4(15)T8',
		'12.4(15)T9',
		'12.4(20)T',
		'12.4(20)T1',
		'12.4(20)T2',
		'12.4(20)T3',
		'12.4(20)T4',
		'12.4(20)T5',
		'12.4(20)T6',
		'12.4(22)T',
		'12.4(22)T1',
		'12.4(22)T2',
		'12.4(22)T3',
		'12.4(22)T4',
		'12.4(22)T5',
		'12.4(24)T',
		'12.4(24)T1',
		'12.4(24)T2',
		'12.4(24)T3',
		'12.4(24)T4',
		'12.4(24)T5',
		'12.4(24)T6',
		'12.4(24)T7',
		'12.4(15)XF',
		'12.4(11)XJ',
		'12.4(11)XJ2',
		'12.4(11)XJ3',
		'12.4(11)XJ4',
		'12.4(14)XK',
		'12.4(11)XV',
		'12.4(11)XV1',
		'12.4(11)XW',
		'12.4(11)XW1',
		'12.4(11)XW10',
		'12.4(11)XW2',
		'12.4(11)XW3',
		'12.4(11)XW4',
		'12.4(11)XW5',
		'12.4(11)XW6',
		'12.4(11)XW7',
		'12.4(11)XW8',
		'12.4(11)XW9',
		'12.4(15)XY',
		'12.4(15)XY1',
		'12.4(15)XY2',
		'12.4(15)XY3',
		'12.4(15)XY4',
		'12.4(15)XY5',
		'12.4(15)XZ',
		'12.4(15)XZ1',
		'12.4(15)XZ2',
		'12.4(20)YA',
		'12.4(20)YA1',
		'12.4(20)YA2',
		'12.4(20)YA3',
		'12.4(22)YB',
		'12.4(22)YB1',
		'12.4(22)YB4',
		'12.4(22)YB5',
		'12.4(22)YB6',
		'12.4(22)YB7',
		'12.4(22)YB8',
		'15.0(1)M',
		'15.0(1)M1',
		'15.0(1)M2',
		'15.0(1)M3',
		'15.0(1)M4',
		'15.0(1)M5',
		'15.0(1)M6',
		'15.0(1)M6a',
		'15.0(1)M7',
		'15.0(1)M8',
		'15.0(1)XA',
		'15.0(1)XA1',
		'15.0(1)XA2',
		'15.0(1)XA3',
		'15.0(1)XA4',
		'15.0(1)XA5',
		'15.1(2)GC',
		'15.1(2)GC1',
		'15.1(2)GC2',
		'15.1(4)M',
		'15.1(4)M0a',
		'15.1(4)M0b',
		'15.1(4)M1',
		'15.1(4)M2',
		'15.1(4)M3',
		'15.1(4)M3a',
		'15.1(4)M4',
		'15.1(1)T',
		'15.1(1)T1',
		'15.1(1)T2',
		'15.1(1)T3',
		'15.1(1)T4',
		'15.1(1)T5',
		'15.1(2)T',
		'15.1(2)T0a',
		'15.1(2)T1',
		'15.1(2)T2',
		'15.1(2)T2a',
		'15.1(2)T3',
		'15.1(2)T4',
		'15.1(2)T5',
		'15.1(3)T',
		'15.1(3)T1',
		'15.1(3)T2',
		'15.1(3)T3',
		'15.1(3)T4',
		'15.1(1)XB',
		'15.1(1)XB1',
		'15.1(4)XB8a',
		'15.2(1)GC',
		'15.2(1)GC1',
		'15.2(1)GC2',
		'15.2(2)GC',
		'15.2(1)T',
		'15.2(1)T1',
		'15.2(1)T2',
		'15.2(2)T',
		'15.2(2)T1',
		'15.2(3)T',
		'15.2(3)T1',
		'15.2(3)XA' );

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

