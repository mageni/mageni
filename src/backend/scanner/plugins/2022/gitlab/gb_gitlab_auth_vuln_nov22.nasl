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

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170218");
  script_version("2022-11-11T14:09:34+0000");
  script_tag(name:"last_modification", value:"2022-11-11 14:09:34 +0000 (Fri, 11 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-11 12:06:24 +0000 (Fri, 11 Nov 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-3413");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 14.5 < 15.3.5, 15.4 < 15.4.4, 15.5 < 15.5.2 Incorrect Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/ee/detected");

  script_tag(name:"summary", value:"GitLab is prone to an incorrect authorization vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Incorrect authorization during display of Audit Events in GitLab EE
  allowed Developers to view the project's Audit Events and Developers or Maintainers to view the
  group's Audit Events. These should have been restricted to Project Maintainers, Group Owners,
  and above.");

  script_tag(name:"affected", value:"GitLab version 14.5.x and above prior to 15.3.5, 15.4.x prior to
  15.4.4 and 15.5.x prior to 15.5.2.");

  script_tag(name:"solution", value:"Update to version 15.3.5, 15.4.4, 15.5.2 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-3413.json");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_in_range_exclusive( version:version, test_version_lo:"14.5", test_version_up:"15.3.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.3.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"15.4", test_version_up:"15.4.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.4.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"15.5", test_version_up:"15.5.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.5.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
