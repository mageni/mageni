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

CPE = "cpe:/a:webnus:modern_events_calendar_lite";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147460");
  script_version("2022-01-18T14:03:41+0000");
  script_tag(name:"last_modification", value:"2022-01-19 11:07:58 +0000 (Wed, 19 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-18 09:09:40 +0000 (Tue, 18 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-16 15:07:00 +0000 (Thu, 16 Dec 2021)");

  script_cve_id("CVE-2021-24925", "CVE-2021-24946");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Modern Events Calendar Lite Plugin < 6.1.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/modern-events-calendar-lite/detected");

  script_tag(name:"summary", value:"The WordPress plugin Modern Events Calendar Lite is prone to
  multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-24925: Reflected cross-site scripting (XSS)

  - CVE-2021-24946: Unauthenticated blind SQL injection (SQLi)");

  script_tag(name:"affected", value:"WordPress Modern Events Calendar Lite plugin through version
  6.1.4.");

  script_tag(name:"solution", value:"Update to version 6.1.5 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/82233588-6033-462d-b886-a8ef5ee9adb0");
  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/09871847-1d6a-4dfe-8a8c-f2f53ff87445");

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

if (version_is_less(version: version, test_version: "6.1.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
