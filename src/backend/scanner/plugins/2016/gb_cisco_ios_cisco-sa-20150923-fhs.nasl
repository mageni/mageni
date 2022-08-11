###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_cisco-sa-20150923-fhs.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# Cisco IOS and IOS XE Software IPv6 First Hop Security Denial of Service Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.105641");
  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12363 $");

  script_name("Cisco IOS and IOS XE Software IPv6 First Hop Security Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-fhs");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20150923-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40940");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewAlert.x?alertId=40941");
  script_xref(name:"URL", value:"http://www.cisco.com/web/about/security/intelligence/Cisco_ERP_sep15.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"Two vulnerabilities in the IPv6 first hop security feature of Cisco IOS and IOS XE Software could allow an unauthenticated, remote attacker to cause an affected device to reload.

  Cisco has released software updates that address these vulnerabilities. There are no workarounds to mitigate these vulnerabilities.
  This advisory is available at the references.

  Note: The September 23, 2015, release of the Cisco IOS and IOS XE Software Security Advisory bundled publication includes three Cisco Security Advisories.
  All the advisories address vulnerabilities in Cisco IOS Software and Cisco IOS XE Software. Individual publication links are in Cisco Event Response:
  September 2015 Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication at the references.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-03 19:33:03 +0200 (Tue, 03 May 2016)");
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
		'12.2(50)SY',
		'12.2(50)SY1',
		'12.2(50)SY2',
		'12.2(50)SY3',
		'12.2(50)SY4',
		'15.0(2)EA2',
		'15.0(2)EJ',
		'15.0(2)EJ1',
		'15.0(1)EX',
		'15.0(2a)EX5',
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
		'15.0(1)SY',
		'15.0(1)SY1',
		'15.0(1)SY2',
		'15.0(1)SY3',
		'15.0(1)SY4',
		'15.0(1)SY5',
		'15.0(1)SY6',
		'15.0(1)SY7',
		'15.0(1)SY7a',
		'15.0(1)SY8',
		'15.1(2)SG',
		'15.1(2)SG1',
		'15.1(2)SG2',
		'15.1(2)SG3',
		'15.1(2)SG4',
		'15.1(2)SG5',
		'15.1(2)SG6',
		'15.1(1)SY',
		'15.1(1)SY1',
		'15.1(1)SY2',
		'15.1(1)SY3',
		'15.1(1)SY4',
		'15.1(1)SY5',
		'15.1(2)SY',
		'15.1(2)SY1',
		'15.1(2)SY2',
		'15.1(2)SY3',
		'15.1(2)SY4',
		'15.1(2)SY4a',
		'15.1(2)SY5',
		'15.2(1)E',
		'15.2(1)E1',
		'15.2(1)E2',
		'15.2(1)E3',
		'15.2(2)E',
		'15.2(2)E1',
		'15.2(2)E2',
		'15.2(2a)E1',
		'15.2(3)E',
		'15.2(3)E1',
		'15.2(3a)E',
		'15.2(2)EA1',
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
		'15.2(1)SY',
		'15.2(1)SY0a',
		'15.3(1)S',
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
		'15.4(1)S',
		'15.4(1)S1',
		'15.4(1)S2',
		'15.4(1)S3',
		'15.4(2)S',
		'15.4(2)S1',
		'15.4(2)S2',
		'15.4(2)S3',
		'15.4(3)S',
		'15.4(3)S1',
		'15.4(3)S2',
		'15.5(1)S',
		'15.5(1)S1' );

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

