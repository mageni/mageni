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
  script_oid("1.3.6.1.4.1.25623.1.0.126019");
  script_version("2022-06-13T03:03:47+0000");
  script_tag(name:"last_modification", value:"2022-06-13 03:03:47 +0000 (Mon, 13 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-03-28 08:06:32 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-02 16:09:00 +0000 (Thu, 02 Jun 2022)");

  script_cve_id("CVE-2022-1413", "CVE-2022-1416", "CVE-2022-1423");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 1.0.2 < 14.8.6, 14.9.0 < 14.9.4, 14.10.0 < 14.10.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-1413: Missing input masking causes potentially sensitive integration properties to be
  disclosed in the web interface

  - CVE-2022-1416: Missing sanitization of data in Pipeline error messages allows for rendering of
  attacker controlled HTML tags and CSS styling

  - CVE-2022-1423: Improper access control in the CI/CD cache mechanism allows a malicious actor
  with Developer privileges to perform cache poisoning leading to arbitrary code execution in
  protected branches");

  script_tag(name:"affected", value:"GitLab version 1.0.2 through 14.8.5, 14.9.0 through 14.9.3
  and version 14.10.0.");

  script_tag(name:"solution", value:"Update to version 14.8.6, 14.9.4, 14.10.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab/-/issues/353720");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1413.json");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab/-/issues/342988");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1416.json");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab/-/issues/330047");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/cves/-/blob/master/2022/CVE-2022-1423.json");
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

if ( version_in_range( version:version, test_version:"1.0.2", test_version2:"14.8.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.8.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"14.9.0", test_version2:"14.9.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.9.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range_exclusive( version:version, test_version_lo:"14.10.0", test_version_up:"14.10.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.1", install_path:location );
}


exit( 99 );
