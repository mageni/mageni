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
  script_oid("1.3.6.1.4.1.25623.1.0.170056");
  script_version("2022-04-04T03:03:57+0000");
  script_tag(name:"last_modification", value:"2022-04-04 10:02:40 +0000 (Mon, 04 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 20:37:22 +0000 (Wed, 23 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-21 17:43:00 +0000 (Fri, 21 Dec 2018)");

  script_cve_id("CVE-2018-18648", "CVE-2018-18644");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 11.2.x - 11.2.6, 11.3.x - 11.3.7, 11.4.x - 11.4.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2018-18648: When parsing a JUnit test report fails, the JSON endpoint exposes the full stack
  trace.

  - CVE-2018-18644: The Projects::Prometheus::AlertsController#create and #update allow an attacker
  to provide an environment_id and prometheus_metric_id that doesn't belong to their project. When an
  alert persists that doesn't belong to their project, they can trigger it using the
  Projects::Prometheus::AlertsController#notify endpoint. This will leak information about the
  victim's environment, project, and their Prometheus metric.");

  script_tag(name:"affected", value:"GitLab version 11.2.x through 11.2.6, 11.3.x through 11.3.7 and
  11.4.x through 11.4.2.");

  script_tag(name:"solution", value:"Update to version 11.2.7, 11.3.8, 11.4.3 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/50975");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab/-/issues/7528");

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

if ( version_in_range( version:version, test_version:"11.2.0", test_version2:"11.2.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.2.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.3.0", test_version2:"11.3.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.3.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.4.0", test_version2:"11.4.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
