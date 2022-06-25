###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_cisco-sa-20160928-fmc.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Cisco Firepower Management Center Software Cross-Site Request Forgery Vulnerability
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106301");
  script_cve_id("CVE-2016-6417");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12096 $");

  script_name("Cisco Firepower Management Center Software Cross-Site Request Forgery Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-fmc");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"A cross-site request forgery (CSRF) vulnerability for Cisco Firepower
Management Center Software could allow an unauthenticated, remote attacker to execute unwanted actions.");

  script_tag(name:"insight", value:"The vulnerability is due to a lack of CSRF protections by an affected device.
An attacker could exploit this vulnerability by convincing a user to follow a malicious link.");

  script_tag(name:"impact", value:"A successful exploit could allow the attacker to submit arbitrary requests
to the affected device via the web browser with the privileges of the user.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-29 14:22:04 +0700 (Thu, 29 Sep 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_version.nasl");
  script_mandatory_keys("cisco_firepower_management_center/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
		'4.10.2',
		'4.10.3',
		'4.10.2.1',
		'4.10.2.2',
		'4.10.2.3',
		'4.10.2.4',
		'4.10.2.5',
		'4.10.3.1',
		'4.10.3.2',
		'4.10.3.3',
		'4.10.3.4',
		'4.10.3.5',
		'4.10.3.6',
		'4.10.3.7',
		'4.10.3.8',
		'4.10.3.9',
		'4.10.3.10',
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
		'6.0.1',
		'6.1.0' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "None Available" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

