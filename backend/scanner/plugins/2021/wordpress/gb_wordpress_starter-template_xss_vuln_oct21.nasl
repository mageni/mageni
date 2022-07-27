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

CPE = "cpe:/a:wpfront:scroll_top";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147252");
  script_version("2021-12-06T06:37:39+0000");
  script_tag(name:"last_modification", value:"2021-12-06 11:03:13 +0000 (Mon, 06 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-06 05:10:27 +0000 (Mon, 06 Dec 2021)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2021-42360");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Starter Templates Plugin < 2.7.1 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/astra-sites/detected");

  script_tag(name:"summary", value:"The WordPress plugin Starter Templates - Elementor, Gutenberg &
  Beaver Builder Templates is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"On sites that also had the Elementor plugin for WordPress
  installed, it is possible for users with the edit_posts capability, which includes
  Contributor-level users, to import blocks onto any page using the
  astra-page-elementor-batch-process AJAX action. An attacker could craft and host a block
  containing malicious JavaScript on a server they controlled, and then use it to overwrite any
  post or page by sending an AJAX request with the action set to astra-page-elementor-batch-process
  and the url parameter pointed to their remotely-hosted malicious block, as well as an id
  parameter containing the post or page to overwrite. Any post or page that had been built with
  Elementor, including published pages, could be overwritten by the imported block, and the
  malicious JavaScript in the imported block would then be executed in the browser of any visitors
  to that page.");

  script_tag(name:"affected", value:"WordPress Starter Templates - Elementor, Gutenberg & Beaver
  Builder Templates prior to version 2.7.1.");

  script_tag(name:"solution", value:"Update to version 2.7.1 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/11/over-1-million-sites-impacted-by-vulnerability-in-starter-templates-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/astra-sites/#developers");

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

if (version_is_less(version: version, test_version: "2.7.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.7.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
