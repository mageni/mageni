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

CPE = "cpe:/a:veronalabs:wp_statistics";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147775");
  script_version("2022-03-09T03:03:43+0000");
  script_tag(name:"last_modification", value:"2022-03-09 11:12:38 +0000 (Wed, 09 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-08 06:40:03 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 03:02:00 +0000 (Thu, 03 Mar 2022)");

  script_cve_id("CVE-2022-0651", "CVE-2022-25148", "CVE-2022-25149", "CVE-2022-25305",
                "CVE-2022-25306", "CVE-2022-25307");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Statistics Plugin < 13.1.6 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-statistics/detected");

  script_tag(name:"summary", value:"The WordPress plugin WP Statistics is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-0651: Unauthenticated blind SQL injection (SQLi) via current_page_type

  - CVE-2022-25148: Unauthenticated blind SQL injection (SQLi) via current_page_id

  - CVE-2022-25149: Unauthenticated blind SQL injection (SQLi) via IP

  - CVE-2022-25305: Unauthenticated stored cross-site scripting (XSS) via IP

  - CVE-2022-25306: Unauthenticated stored cross-site scripting (XSS) via browser

  - CVE-2022-25307: Unauthenticated stored cross-site scripting (XSS) via platform");

  script_tag(name:"affected", value:"WordPress WP Statistics plugin through version 13.1.5.");

  script_tag(name:"solution", value:"Update to version 13.1.6 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-0651");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-25148");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-25149");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-25305");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-25306");
  script_xref(name:"URL", value:"https://www.wordfence.com/vulnerability-advisories/#CVE-2022-25307");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "13.1.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.1.6", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
