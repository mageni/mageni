# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.112855");
  script_version("2021-01-15T15:19:49+0000");
  script_tag(name:"last_modification", value:"2021-01-18 11:03:31 +0000 (Mon, 18 Jan 2021)");
  script_tag(name:"creation_date", value:"2021-01-14 11:57:11 +0000 (Thu, 14 Jan 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-35701");

  script_name("Cacti 1.2.x < 1.2.17 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - A vulnerability in data_debug.php allows remote authenticated
  attackers to execute arbitrary SQL commands via the site_id parameter

  - Multiple stored cross-site scripting vulnerabilities");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker
  to execute arbitrary SQL commands or JavaScript code.");

  script_tag(name:"affected", value:"Cacti 1.2.x through 1.2.16.");

  script_tag(name:"solution", value:"Update Cacti to version 1.2.17 or later.");

  script_xref(name:"URL", value:"https://asaf.me/2020/12/15/cacti-1-2-0-to-1-2-16-sql-injection/");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/4022");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/4019");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/4035");

  exit(0);
}

CPE = "cpe:/a:cacti:cacti";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version: version, test_version: "1.2.0", test_version2: "1.2.16" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "1.2.17", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
