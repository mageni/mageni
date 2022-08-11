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
  script_oid("1.3.6.1.4.1.25623.1.0.170094");
  script_version("2022-03-31T18:21:17+0000");
  script_tag(name:"last_modification", value:"2022-04-04 10:02:40 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-25 19:01:02 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");

  script_cve_id("CVE-2022-0735", "CVE-2022-0549", "CVE-2022-0751", "CVE-2022-0741", "CVE-2021-4191", "CVE-2022-0738", "CVE-2022-0489");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 12.10.x - 14.6.4, 14.7.x - 14.7.3, 14.8.x - 14.8.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-0735: runner registration token disclosure through Quick Actions

  - CVE-2022-0549: unprivileged users can add other users to groups through an API endpoint

  - CVE-2022-0751: inaccurate display of Snippet contents can be potentially misleading to users

  - CVE-2022-0741: environment variables can be leaked via the sendmail delivery method

  - CVE-2021-4191: unauthenticated user enumeration on GraphQL API

  - CVE-2022-0738: adding a mirror with SSH credentials can leak password

  - CVE-2022-0489: Denial of Service via user comments");

  script_tag(name:"affected", value:"GitLab version 12.10.x through 14.6.4, 14.7.x through 14.7.3 and
  14.8.x through 14.8.1.");

  script_tag(name:"solution", value:"Update to version 14.6.5, 14.7.4 or 14.8.2 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/02/25/critical-security-release-gitlab-14-8-2-released/");

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

if ( version_in_range( version:version, test_version:"12.10.0", test_version2:"14.6.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.6.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"14.7.0", test_version2:"14.7.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.7.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"14.8.0", test_version2:"14.8.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.8.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
