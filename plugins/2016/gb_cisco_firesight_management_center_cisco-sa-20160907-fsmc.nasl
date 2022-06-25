###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_management_center_cisco-sa-20160907-fsmc.nasl 12313 2018-11-12 08:53:51Z asteins $
#
# Cisco FireSIGHT System Software Session Fixation Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106234");
  script_cve_id("CVE-2016-6394");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_version("$Revision: 12313 $");

  script_name("Cisco FireSIGHT System Software Session Fixation Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160907-fsmc");
  script_xref(name:"URL", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuz80503");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to version 6.1.0.1 or later. Please see the references for more information.");
  script_tag(name:"summary", value:"A vulnerability in session identification management functionality of the
web-based management interface for Cisco FireSIGHT System Software could allow an unauthenticated, remote
attacker to hijack a valid user session.

The vulnerability exists because the affected application does not assign a new session identifier to a user
session when a user authenticates to the application. An attacker could exploit this vulnerability by using a
hijacked session identifier to connect to the application through the web-based management interface. A
successful exploit could allow the attacker to hijack an authenticated user's browser session.

Cisco has not released software updates that address this vulnerability. There are no workarounds that address
this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-12 09:53:51 +0100 (Mon, 12 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-08 10:51:23 +0700 (Thu, 08 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl", "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
		'5.2.0',
		'5.2.0.1',
		'5.2.0.2',
		'5.2.0.3',
		'5.2.0.4',
		'5.2.0.5',
		'5.2.0.6',
		'5.2.0.8',
		'5.3.0',
		'5.3.0.1',
		'5.3.0.2',
		'5.3.0.3',
		'5.3.0.4',
		'5.3.0.5',
		'5.3.0.6',
		'5.3.0.7',
		'5.3.1.1',
		'5.3.1.2',
		'5.3.1.3',
		'5.3.1',
		'5.3.1.5',
		'5.3.1.4',
		'5.3.1.7',
		'5.4.0',
		'5.4.0.1',
		'5.4.0.2',
		'5.4.0.3',
		'5.4.0.4',
		'5.4.0.5',
		'5.4.0.6',
		'5.4.1',
		'5.4.1.2',
		'5.4.1.3',
		'5.4.1.4',
		'6.0.0',
		'6.0.0.1',
		'6.0.1',
		'6.1.0' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "6.1.0.1" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

