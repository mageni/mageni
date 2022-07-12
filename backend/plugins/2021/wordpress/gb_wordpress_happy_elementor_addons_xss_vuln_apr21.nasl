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

CPE = "cpe:/a:wedevs:happy_addons_for_elementor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146076");
  script_version("2021-06-04T03:54:14+0000");
  script_tag(name:"last_modification", value:"2021-06-04 10:13:25 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-04 03:30:35 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-24292");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Happy Addons for Elementor Plugin < 2.24.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/happy-elementor-addons/detected");

  script_tag(name:"summary", value:"WordPress Happy Addons for Elementor plugin is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The Happy Addons for Elementor WordPress plugin has a number of
  widgets that are vulnerable to stored XSS by lower-privileged users such as contributors, all via
  a similar method: The 'Card' widget accepts a 'title_tag' parameter. Although the element control
  lists a fixed set of possible html tags, it is possible to send a 'save_builder' request with the
  'heading_tag' set to 'script', and the actual 'title' parameter set to JavaScript to be executed
  within the script tags added by the 'heading_tag' parameter.");

  script_tag(name:"affected", value:"WordPress Happy Addons for Elementor plugin prior to version
  2.24.0.");

  script_tag(name:"solution", value:"Update to version 2.24.0 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/happy-elementor-addons/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/04/recent-patches-rock-the-elementor-ecosystem/");

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

if (version_is_less(version: version, test_version: "2.24.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.24.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
