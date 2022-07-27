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

CPE = "cpe:/a:fontsplugin:fonts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146886");
  script_version("2021-10-12T14:01:30+0000");
  script_tag(name:"last_modification", value:"2021-10-13 11:12:06 +0000 (Wed, 13 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-10-12 12:20:09 +0000 (Tue, 12 Oct 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-01 17:32:00 +0000 (Fri, 01 Oct 2021)");

  script_cve_id("CVE-2021-24637");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Google Fonts Typography Plugin < 3.0.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/olympus-google-fonts/detected");

  script_tag(name:"summary", value:"The WordPress plugin Google Fonts Typography is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin does not escape and sanitise some of its block
  settings, allowing users with as role as low as Contributor to perform stored XSS attacks via
  blockType (combined with content), align, color, variant and fontID argument of a Gutenberg block.");

  script_tag(name:"affected", value:"WordPress Google Fonts Typography plugin through version 3.0.2.");

  script_tag(name:"solution", value:"Update to version 3.0.3 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/dd2b3f22-5e8b-41cf-bcb8-d2e673e1d21e");
  script_xref(name:"URL", value:"https://raw.githubusercontent.com/dannycooper/olympus-google-fonts/master/changelog.txt");

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

if (version_is_less(version: version, test_version: "3.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
