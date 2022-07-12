###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20160323-ios-ikev2.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Cisco IOS and IOS XE Software Internet Key Exchange Version 2 Fragmentation Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105638");
  script_cve_id("CVE-2016-1344");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12363 $");

  script_name("Cisco IOS and IOS XE Software Internet Key Exchange Version 2 Fragmentation Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-ios-ikev2");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20160323-bundle");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Internet Key Exchange (IKE) version 2 (v2) fragmentation code of Cisco IOS and IOS XE Software could allow an unauthenticated,
  remote attacker to cause a reload of the affected system.

  The vulnerability is due to an improper handling of crafted, fragmented IKEv2 packets. An attacker could exploit this vulnerability by
  sending crafted UDP packets to the affected system. An exploit
  could allow the attacker to cause a reload of the affected system.

  Note: Only traffic directed to the affected system can
  be used to exploit this vulnerability. This vulnerability can be triggered by IPv4 and
  IPv6 traffic.

  Cisco has released software updates that address this vulnerability.
  This advisory is available at the references.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication,
  which includes six Cisco Security Advisories that describe six vulnerabilities. All the vulnerabilities have a Security Impact Rating of `High.`
  For a complete list of advisories and links to them, see Cisco Event Response: Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 19:27:21 +0200 (Tue, 03 May 2016)");
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
		'15.0(2)ED',
		'15.0(2)ED1',
		'15.0(2)EH',
		'15.0(2)EJ',
		'15.0(2)EJ1',
		'15.0(2)EK',
		'15.0(2)EK1',
		'15.0(2)EX',
		'15.0(2)EX1',
		'15.0(2)EX3',
		'15.0(2)EX4',
		'15.0(2)EX5',
		'15.0(2a)EX5',
		'15.0(2)EY',
		'15.0(2)EY1',
		'15.0(2)EY3',
		'15.0(2)EZ',
		'15.0(2)SE',
		'15.0(2)SE1',
		'15.0(2)SE2',
		'15.0(2)SE3',
		'15.0(2)SE4',
		'15.0(2)SE5',
		'15.0(2)SE6',
		'15.0(2)SE7',
		'15.0(2)SE8',
		'15.0(2)SE9',
		'15.0(2a)SE9',
		'15.1(4)GC',
		'15.1(4)GC1',
		'15.1(4)GC2',
		'15.1(4)M',
		'15.1(4)M1',
		'15.1(4)M10',
		'15.1(4)M2',
		'15.1(4)M3',
		'15.1(4)M3a',
		'15.1(4)M4',
		'15.1(4)M5',
		'15.1(4)M6',
		'15.1(4)M7',
		'15.1(4)M8',
		'15.1(4)M9',
		'15.1(3)MR',
		'15.1(3)MRA',
		'15.1(3)MRA1',
		'15.1(3)MRA2',
		'15.1(3)MRA3',
		'15.1(3)MRA4',
		'15.1(2)S',
		'15.1(2)S1',
		'15.1(2)S2',
		'15.1(3)S',
		'15.1(3)S0a',
		'15.1(3)S1',
		'15.1(3)S2',
		'15.1(3)S3',
		'15.1(3)S4',
		'15.1(3)S5',
		'15.1(3)S5a',
		'15.1(3)S6',
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
		'15.1(2)SNG',
		'15.1(2)SNH',
		'15.1(2)SNI',
		'15.1(2)SNI1',
		'15.1(1)SY',
		'15.1(1)SY1',
		'15.1(1)SY2',
		'15.1(1)SY3',
		'15.1(1)SY4',
		'15.1(1)SY5',
		'15.1(1)SY6',
		'15.1(2)SY',
		'15.1(2)SY1',
		'15.1(2)SY2',
		'15.1(2)SY3',
		'15.1(2)SY4',
		'15.1(2)SY4a',
		'15.1(2)SY5',
		'15.1(2)SY6',
		'15.1(3)T',
		'15.1(3)T1',
		'15.1(3)T2',
		'15.1(3)T3',
		'15.1(3)T4',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)E2',
		'15.2(1)E3',
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2)E3',
		'15.2(2a)E1',
		'15.2(2a)E2',
		'15.2(3)E',
		'15.2(3)E1',
		'15.2(3)E2',
		'15.2(3)E3',
		'15.2(3a)E',
		'15.2(3m)E2',
		'15.2(4)E',
		'15.2(4)E1',
		'15.2(2)EB',
		'15.2(2)EB1',
		'15.2(1)EY',
		'15.2(2)EA1',
		'15.2(2)EA2',
		'15.2(3)EA',
		'15.2(4)EA',
		'15.2(1)GC',
		'15.2(1)GC1',
		'15.2(1)GC2',
		'15.2(2)GC',
		'15.2(3)GC',
		'15.2(3)GC1',
		'15.2(4)GC',
		'15.2(4)GC1',
		'15.2(4)GC2',
		'15.2(4)GC3',
		'15.2(4)M',
		'15.2(4)M1',
		'15.2(4)M2',
		'15.2(4)M3',
		'15.2(4)M4',
		'15.2(4)M5',
		'15.2(4)M6',
		'15.2(4)M6a',
		'15.2(4)M7',
		'15.2(4)M8',
		'15.2(4)M9',
		'15.2(1)S',
		'15.2(1)S1',
		'15.2(1)S2',
		'15.2(2)S',
		'15.2(2)S1',
		'15.2(2)S2',
		'15.2(4)S',
		'15.2(4)S1',
		'15.2(4)S2',
		'15.2(4)S3',
		'15.2(4)S3a',
		'15.2(4)S4',
		'15.2(4)S4a',
		'15.2(4)S5',
		'15.2(4)S6',
		'15.2(4)S7',
		'15.2(2)SNG',
		'15.2(2)SNH1',
		'15.2(2)SNI',
		'15.2(1)SY',
		'15.2(1)SY0a',
		'15.2(1)SY1',
		'15.2(1)SY1a',
		'15.2(2)SY',
		'15.2(1)T',
		'15.2(1)T1',
		'15.2(1)T2',
		'15.2(1)T3',
		'15.2(1)T3a',
		'15.2(1)T4',
		'15.2(2)T',
		'15.2(2)T1',
		'15.2(2)T2',
		'15.2(2)T3',
		'15.2(2)T4',
		'15.2(3)T',
		'15.2(3)T1',
		'15.2(3)T2',
		'15.2(3)T3',
		'15.2(3)T4',
		'15.3(3)M',
		'15.3(3)M1',
		'15.3(3)M2',
		'15.3(3)M3',
		'15.3(3)M4',
		'15.3(3)M5',
		'15.3(3)M6',
		'15.3(1)S',
		'15.3(1)S1',
		'15.3(1)S2',
		'15.3(2)S',
		'15.3(2)S0a',
		'15.3(2)S1',
		'15.3(2)S2',
		'15.3(3)S',
		'15.3(3)S1',
		'15.3(3)S2',
		'15.3(3)S3',
		'15.3(3)S4',
		'15.3(3)S5',
		'15.3(3)S6',
		'15.3(1)T',
		'15.3(1)T1',
		'15.3(1)T2',
		'15.3(1)T3',
		'15.3(1)T4',
		'15.3(2)T',
		'15.3(2)T1',
		'15.3(2)T2',
		'15.3(2)T3',
		'15.3(2)T4',
		'15.4(1)CG',
		'15.4(1)CG1',
		'15.4(2)CG',
		'15.4(3)M',
		'15.4(3)M1',
		'15.4(3)M2',
		'15.4(3)M3',
		'15.4(3)M4',
		'15.4(1)S',
		'15.4(1)S1',
		'15.4(1)S2',
		'15.4(1)S3',
		'15.4(1)S4',
		'15.4(2)S',
		'15.4(2)S1',
		'15.4(2)S2',
		'15.4(2)S3',
		'15.4(2)S4',
		'15.4(3)S',
		'15.4(3)S1',
		'15.4(3)S2',
		'15.4(3)S3',
		'15.4(3)S4',
		'15.4(1)T',
		'15.4(1)T1',
		'15.4(1)T2',
		'15.4(1)T3',
		'15.4(1)T4',
		'15.4(2)T',
		'15.4(2)T1',
		'15.4(2)T2',
		'15.4(2)T3',
		'15.4(2)T4',
		'15.5(3)M',
		'15.5(3)M0a',
		'15.5(3)M1',
		'15.5(1)S',
		'15.5(1)S1',
		'15.5(1)S2',
		'15.5(1)S3',
		'15.5(2)S',
		'15.5(2)S1',
		'15.5(2)S2',
		'15.5(3)S',
		'15.5(3)S0a',
		'15.5(3)S1',
		'15.5(3)S1a',
		'15.5(3)SN',
		'15.5(1)T',
		'15.5(1)T1',
		'15.5(1)T2',
		'15.5(1)T3',
		'15.5(2)T',
		'15.5(2)T1',
		'15.5(2)T2',
		'15.6(1)T0a' );

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

