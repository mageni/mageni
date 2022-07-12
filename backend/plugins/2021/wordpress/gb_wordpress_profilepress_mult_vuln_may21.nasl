# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:profilepress:profilepress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146796");
  script_version("2021-09-28T15:12:33+0000");
  script_tag(name:"last_modification", value:"2021-09-29 10:16:16 +0000 (Wed, 29 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-28 14:52:27 +0000 (Tue, 28 Sep 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-34621", "CVE-2021-34622", "CVE-2021-34623", "CVE-2021-34624");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress ProfilePress Plugin 3.0.0 < 3.1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/wp-user-avatar/detected");

  script_tag(name:"summary", value:"ProfilePress (Formerly WP User Avatar) for WordPress is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-34621: Possibility for users to register on sites as an administrator

  - CVE-2021-34622: Possibility for users to escalate their privileges to that of an administrator
  while editing their profile

  - CVE-2021-34623: Possibility for users to upload arbitrary files during user registration or
  during profile updates

  - CVE-2021-34624: Possibility for users to upload arbitrary files during user registration or
  during profile updates");

  script_tag(name:"affected", value:"WordPress ProfilePress plugin version 3.0.0 through 3.1.3.");

  script_tag(name:"solution", value:"Update to version 3.1.4 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/06/easily-exploitable-critical-vulnerabilities-patched-in-profilepress-plugin/");

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

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.1.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
