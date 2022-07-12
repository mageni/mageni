###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_management_center_cisco-sa-20160907-fsss1.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Cisco FireSIGHT System Software Malware Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.106233");
  script_cve_id("CVE-2016-6396");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12431 $");

  script_name("Cisco FireSIGHT System Software Malware Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160907-fsss1");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the malicious file detection and blocking features of
Cisco FireSIGHT System Software could allow an unauthenticated, remote attacker to bypass malware detection
mechanisms on an affected system.

The vulnerability is due to improper input validation of fields in HTTP headers. An attacker could exploit this
vulnerability by crafting specific file content on a server or persuading a user to click a specific link. A
successful exploit could allow the attacker to bypass malicious file detection or blocking policies that are
configured for the system, which could allow malware to pass through the system undetected.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-08 10:40:02 +0700 (Thu, 08 Sep 2016)");
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
		'5.1.0',
		'5.1.0.1',
		'5.1.0.2',
		'5.1.0.3',
		'5.1.1',
		'5.1.1.1',
		'5.1.1.2',
		'5.1.1.3',
		'5.1.1.4',
		'5.1.1,5',
		'5.1.1.6',
		'5.1.1.8',
		'5.1.1.9',
		'5.1.1.10',
		'5.1.1.11',
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
		'6.0.1' );

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

