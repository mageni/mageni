# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113352");
  script_version("$Revision: 14196 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 08:20:59 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-12 12:57:05 +0200 (Tue, 12 Mar 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2013-7466", "CVE-2013-7467", "CVE-2013-7468");

  script_name("Simple Machines Forum <= 2.0.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simple_machines_forum_detect.nasl");
  script_mandatory_keys("SMF/installed");

  script_tag(name:"summary", value:"Simple Machines Forum is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Following vulnerabilities exist:

  - XSS via the index.php?action=pm, sa=settings, save sa parameter

  - PHP Code Injection via the
    index.php?action=admin, area=languages, sa=editlang dictionary parameter

  - local file inclusion, with resultant remote code execution,
    in install.php via ../ directory traversal in the db_type parameter
    if install.php remains present after installation");
  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to gain full
  control over the target system.");
  script_tag(name:"affected", value:"Simple Machines Forum through version 2.0.4.");
  script_tag(name:"solution", value:"Update to version 2.0.5.");

  script_xref(name:"URL", value:"http://hauntit.blogspot.com/2013/04/en-smf-204-full-disclosure.html");

  exit(0);
}

CPE = "cpe:/a:simplemachines:smf";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "2.0.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.0.5" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
