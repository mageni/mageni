###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ios_xe_cisco-sa-20160323-smi.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Cisco IOS and IOS XE Software Smart Install Denial of Service Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105665");
  script_cve_id("CVE-2016-1349");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_version("$Revision: 12149 $");

  script_name("Cisco IOS and IOS XE Software Smart Install Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-smi");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityBundle/cisco-sa-20160323-bundle");
  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-51122");


  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"The Smart Install client feature in Cisco IOS and IOS XE Software contains
  a vulnerability that could allow an unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.

  The vulnerability is due to incorrect handling of image list parameters. An attacker could exploit this
  vulnerability by sending crafted Smart Install packets to TCP port 4786. A successful exploit could cause
  a Cisco Catalyst switch to reload, resulting in a DoS condition.

  Cisco has released software updates that address this vulnerability. There are no workarounds that address
  this vulnerability other than disabling Smart Install functionality on the vulnerable device.

  This advisory is part of the March 23, 2016, release of the Cisco IOS and IOS XE Software Security Advisory Bundled Publication,
  which includes six Cisco Security Advisories that describe six vulnerabilities. All the vulnerabilities have a Security Impact Rating of `High.`
  For a complete list of advisories and links to them, see Cisco Event Response: Semiannual Cisco IOS and IOS XE Software Security Advisory Bundled Publication.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-09 17:38:16 +0200 (Mon, 09 May 2016)");
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
		'3.2.0JA',
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
		'3.6.1E',
		'3.6.2aE',
		'3.6.2E',
		'3.7.0E',
		'3.7.1E',
		'3.7.2E' );

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

