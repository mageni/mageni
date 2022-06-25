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

CPE = "cpe:/a:brainstormforce:elementor_-_header%2c_footer_%26_blocks_template";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145950");
  script_version("2021-05-17T04:48:26+0000");
  script_tag(name:"last_modification", value:"2021-05-18 10:15:22 +0000 (Tue, 18 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-17 04:11:06 +0000 (Mon, 17 May 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24256");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Elementor - Header, Footer & Blocks Template Plugin < 1.5.8 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/header-footer-elementor/detected");

  script_tag(name:"summary", value:"The WordPress plugin Elementor - Header, Footer & Blocks Template
  is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Elementor - Header, Footer & Blocks Template Plugin has two
  widgets that are vulnerable to stored XSS by lower-privileged users such as contributors, all via
  a similar method.");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to
  inject arbitrary HTML and JavaScript into the site.");

  script_tag(name:"affected", value:"WordPress Elementor - Header, Footer & Blocks Template plugin
  prior to version 1.5.8.");

  script_tag(name:"solution", value:"Update to version 1.5.8 or later.");

  script_xref(name:"URL", value:"https://wpscan.com/vulnerability/a9412fed-aed3-4931-a504-1a86f876892e");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/header-footer-elementor/#developers");

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

if (version_is_less(version: version, test_version: "1.5.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
