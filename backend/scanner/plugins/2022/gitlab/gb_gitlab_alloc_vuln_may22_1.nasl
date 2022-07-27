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
  script_oid("1.3.6.1.4.1.25623.1.0.126009");
  script_version("2022-06-14T14:05:23+0000");
  script_tag(name:"last_modification", value:"2022-06-15 10:13:29 +0000 (Wed, 15 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-14 08:34:10 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-18 19:56:00 +0000 (Wed, 18 May 2022)");

  script_cve_id("CVE-2022-1428");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab < 14.8.6, 14.9.x < 14.9.4, 14.10.x < 14.10.1 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GitLab is incorrectly verifying throttling limits for
  authenticated package requests which resulted in limits not being enforced.");

  script_tag(name:"affected", value:"GitLab prior to version 14.8.6, 14.9.x through 14.9.3 and
  version 14.10.0.");

  script_tag(name:"solution", value:"Update to version 14.8.6, 14.9.4, 14.10.1 or later");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/");

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

if ( version_is_less( version:version, test_version:"14.8.6" ) ) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.8.6", install_path:location);
    security_message(port: port, data: report);
    exit(0);
}

if ( version_in_range( version:version, test_version:"14.9.0", test_version2:"14.9.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.9.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"14.10.0") ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
