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
  script_oid("1.3.6.1.4.1.25623.1.0.126015");
  script_version("2022-06-09T03:04:58+0000");
  script_tag(name:"last_modification", value:"2022-06-09 10:10:35 +0000 (Thu, 09 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-03-28 08:06:32 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-08 19:36:00 +0000 (Fri, 08 Apr 2022)");

  script_cve_id("CVE-2021-39908");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 0.8.x < 14.2.6, 14.3.x < 14.3.4, 14.4.x < 14.4.1 Code Injection Vulnerability.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a code injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Certain Unicode characters can be abused to commit malicious
  code into projects without being noticed in merge request or source code viewer UI.");

  script_tag(name:"affected", value:"GitLab version 0.8.0 through 14.2.5, 14.3.0 through 14.3.3
  and version 14.4.0.");

  script_tag(name:"solution", value:"Update to version 14.2.6, 14.3.4, 14.4.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2021/10/28/security-release-gitlab-14-4-1-released/");

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

if ( version_in_range( version:version, test_version:"0.8.0", test_version2:"14.2.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.2.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"14.3.0", test_version2:"14.3.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.3.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.4.0", test_version_up:"14.4.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.4.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
