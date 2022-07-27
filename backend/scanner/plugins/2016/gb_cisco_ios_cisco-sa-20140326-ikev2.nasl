###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20140326-ikev2.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco IOS Software Internet Key Exchange Version 2 Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105650");
  script_cve_id("CVE-2014-2108");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12149 $");

  script_name("Cisco IOS Software Internet Key Exchange Version 2 Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ikev2");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20140326-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=33346");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_mar14.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the Internet Key Exchange Version 2 (IKEv2) module
  of Cisco IOS Software and Cisco IOS XE Software could allow an unauthenticated, remote attacker to cause
  a reload of the affected device that would lead to a denial of service (DoS) condition.

  The vulnerability is due to how an affected device processes certain malformed IKEv2 packets.
  An attacker could exploit this vulnerability by sending malformed IKEv2 packets to an affected
  device to be processed. An exploit could allow the attacker to cause a reload of the affected
  device that would lead to a DoS condition.

  Although IKEv2 is automatically enabled on Cisco IOS Software and Cisco IOS XE Software devices
  when the Internet Security Association and Key Management Protocol (ISAKMP) is enabled,
  the vulnerability can be triggered only by sending a malformed IKEv2 packet.

  Only IKEv2 packets can trigger this vulnerability.

  Cisco has released software updates that address this vulnerability. There are no workarounds to mitigate this vulnerability.

  Note: The March 26, 2014, Cisco IOS Software Security Advisory bundled publication includes six Cisco Security Advisories.
  All advisories address vulnerabilities in Cisco IOS Software. Each Cisco IOS Software Security Advisory lists the Cisco
  IOS Software releases that correct the vulnerability or vulnerabilities detailed in the advisory as well as the Cisco IOS
  Software releases that correct all Cisco IOS Software vulnerabilities in the March 2014 bundled publication.

  Individual publication links are in Cisco Event Response: Semiannual Cisco IOS Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-04 18:49:42 +0200 (Wed, 04 May 2016)");
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
		'15.0(2)EX',
		'15.0(2)EX1',
		'15.0(2)EX3',
		'15.0(2)EX4',
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
		'15.1(2)GC',
		'15.1(2)GC1',
		'15.1(2)GC2',
		'15.1(4)GC',
		'15.1(4)GC1',
		'15.1(4)GC2',
		'15.1(4)M',
		'15.1(4)M0a',
		'15.1(4)M0b',
		'15.1(4)M1',
		'15.1(4)M2',
		'15.1(4)M3',
		'15.1(4)M3a',
		'15.1(4)M4',
		'15.1(4)M5',
		'15.1(4)M6',
		'15.1(4)M7',
		'15.1(1)MR',
		'15.1(1)MR1',
		'15.1(1)MR2',
		'15.1(1)MR3',
		'15.1(1)MR4',
		'15.1(1)MR5',
		'15.1(1)MR6',
		'15.1(3)MR',
		'15.1(3)MRA',
		'15.1(3)MRA1',
		'15.1(3)MRA2',
		'15.1(1)S',
		'15.1(1)S1',
		'15.1(1)S2',
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
		'15.1(2)SNG',
		'15.1(2)SNH',
		'15.1(2)SNH1',
		'15.1(2)SNI',
		'15.1(2)SNI1',
		'15.1(1)SY',
		'15.1(1)SY1',
		'15.1(1)SY2',
		'15.1(2)SY',
		'15.1(2)SY1',
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
		'15.1(1)XB1',
		'15.1(4)XB8',
		'15.1(4)XB8a',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)EY',
		'15.2(1)GC',
		'15.2(1)GC1',
		'15.2(1)GC2',
		'15.2(2)GC',
		'15.2(3)GC',
		'15.2(3)GC1',
		'15.2(4)GC',
		'15.2(3)GCA',
		'15.2(3)GCA1',
		'15.2(4)M',
		'15.2(4)M1',
		'15.2(4)M2',
		'15.2(4)M3',
		'15.2(4)M4',
		'15.2(4)M5',
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
		'15.2(2)SNG',
		'15.2(2)SNH',
		'15.2(2)SNH1',
		'15.2(2)SNI',
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
		'15.2(3)XA',
		'15.2(4)XB10',
		'15.3(3)M',
		'15.3(1)S',
		'15.3(1)S1',
		'15.3(1)S2',
		'15.3(2)S',
		'15.3(2)S0a',
		'15.3(2)S0xa',
		'15.3(2)S1',
		'15.3(2)S2',
		'15.3(3)S',
		'15.3(1)T',
		'15.3(1)T1',
		'15.3(1)T2',
		'15.3(1)T3',
		'15.3(2)T',
		'15.3(2)T1' );

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

