# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:thewpninjas:ninja-forms";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146888");
  script_version("2021-10-12T14:01:30+0000");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-12 12:37:05 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-29 18:46:00 +0000 (Wed, 29 Sep 2021)");

  script_cve_id("CVE-2021-34647", "CVE-2021-34648");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ninja Forms Plugin < 3.5.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/ninja-forms/detected");

  script_tag(name:"summary", value:"The Ninja Forms plugin for WordPress is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-34647: Unprotected REST-API to sensitive information disclosure

  - CVE-2021-34648: Unprotected REST-API to email injection");

  script_tag(name:"affected", value:"WordPress Ninja Forms plugin through version 3.5.7.");

  script_tag(name:"solution", value:"Update to version 3.5.8 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/09/recently-patched-vulnerabilities-in-ninja-forms-plugin-affects-over-1-million-site-owners/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ninja-forms/#developers");

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

if (version_is_less(version: version, test_version: "3.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
