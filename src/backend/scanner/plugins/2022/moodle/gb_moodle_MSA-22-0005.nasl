# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:moodle:moodle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.118426");
  script_version("2022-12-05T10:11:03+0000");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-01 15:41:26 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-30 19:16:00 +0000 (Wed, 30 Mar 2022)");

  script_cve_id("CVE-2022-0983");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Moodle < 3.9.13, 3.10.x < 3.10.10, 3.11.x < 3.11.6 SQLi Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl");
  script_mandatory_keys("moodle/detected");

  script_tag(name:"summary", value:"Moodle is prone to an sql injection (SQLi) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An SQL injection risk was identified in Badges code relating
  to configuring criteria. Access to the relevant capability was limited to teachers and managers
  by default.");

  script_tag(name:"affected", value:"Moodle prior to version 3.9.13, versions 3.10.x through 3.10.9
  and 3.11.x through 3.11.5.");

  script_tag(name:"solution", value:"Update to version 3.9.13, 3.10.10, 3.11.6 or later.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=432947");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"3.9.13" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.10.0", test_version2:"3.10.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.10.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"3.11.0", test_version2:"3.11.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.11.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
