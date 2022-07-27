###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20150923-fhs.nasl 12338 2018-11-13 14:51:17Z asteins $
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

CPE = "cpe:/o:cisco:ios_xe";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105669");
  script_cve_id("CVE-2015-6278", "CVE-2015-6279");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12338 $");

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

  script_tag(name:"last_modification", value:"$Date: 2018-11-13 15:51:17 +0100 (Tue, 13 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-05-09 18:25:53 +0200 (Mon, 09 May 2016)");
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
		'3.2.0SE',
		'3.2.1SE',
		'3.2.2SE',
		'3.2.3SE',
		'3.3.0SE',
		'3.3.1SE',
		'3.3.2SE',
		'3.3.3SE',
		'3.3.4SE',
		'3.3.5SE',
		'3.3.0XO',
		'3.3.1XO',
		'3.3.2XO',
		'3.4.0SG',
		'3.4.1SG',
		'3.4.2SG',
		'3.4.3SG',
		'3.4.4SG',
		'3.4.5SG',
		'3.4.6SG',
		'3.5.0E',
		'3.5.1E',
		'3.5.2E',
		'3.5.3E',
		'3.6.0E',
		'3.6.0E',
		'3.6.0E',
		'3.6.1E',
		'3.6.2E',
		'3.6.2E',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E',
		'3.9.0S',
		'3.9.1S',
		'3.9.2S',
		'3.10.0S',
		'3.10.0S',
		'3.10.1S',
		'3.10.2S',
		'3.10.3S',
		'3.10.4S',
		'3.10.5S',
		'3.10.01S',
		'3.11.0S',
		'3.11.1S',
		'3.11.2S',
		'3.11.3S',
		'3.12.0S',
		'3.12.1S',
		'3.12.2S',
		'3.12.3S',
		'3.13.0S',
		'3.13.1S',
		'3.13.2S',
		'3.14.0S',
		'3.14.1S' );

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

