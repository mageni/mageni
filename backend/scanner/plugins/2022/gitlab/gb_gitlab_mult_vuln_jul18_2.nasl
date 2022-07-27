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
  script_oid("1.3.6.1.4.1.25623.1.0.170064");
  script_version("2022-04-04T03:03:57+0000");
  script_tag(name:"last_modification", value:"2022-04-04 10:02:40 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-28 14:21:05 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-18 18:17:00 +0000 (Tue, 18 Sep 2018)");

  script_cve_id("CVE-2018-14602", "CVE-2018-14603", "CVE-2018-14604", "CVE-2018-14605", "CVE-2018-14606");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab <= 10.8.6, 11.x - 11.0.4, 11.1.x - 11.1.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-14602: monitor.gitlab.net exposes private information

  - CVE-2018-14603: CSRF can occur in the Test feature of the System Hooks component

  - CVE-2018-14604: XSS can occur in the tooltip of the job inside the CI/CD pipeline

  - CVE-2018-14605: XSS can occur in the branch name during a Web IDE file commit

  - CVE-2018-14606: stored XSS when promoting Milestone inside Notification");

  script_tag(name:"affected", value:"GitLab version 10.8.6 and prior, 11.x through 11.0.4 and
  11.1.x through 11.1.1.");

  script_tag(name:"solution", value:"Update to version 10.8.7, 11.0.5, 11.1.2 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-com/gl-infra/reliability/-/issues/4423");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/48617");

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

if ( version_is_less( version:version, test_version:"10.8.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.8.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.0.0", test_version2:"11.0.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.0.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.1.0", test_version2:"11.1.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.1.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
