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

CPE = "cpe:/a:nextscripts:social-networks-auto-poster-facebook-twitter-g";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147160");
  script_version("2021-11-16T03:39:55+0000");
  script_tag(name:"last_modification", value:"2021-11-16 11:18:47 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-16 02:17:23 +0000 (Tue, 16 Nov 2021)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2021-38356");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Social Networks Auto-Poster Plugin < 4.3.21 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/social-networks-auto-poster-facebook-twitter-g/detected");

  script_tag(name:"summary", value:"The WordPress plugin Social Networks Auto-Poster is prone to a
  cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin is vulnerable to a reflected XSS via the
  $_REQUEST['page'] parameter which is echoed out on inc/nxs_class_snap.php by supplying the
  appropriate value 'nxssnap-post' to load the page in $_GET['page'] along with malicious
  JavaScript in $_POST['page'].");

  script_tag(name:"affected", value:"WordPress Social Networks Auto-Poster plugin version 4.3.20
  and prior.");

  script_tag(name:"solution", value:"Update to version 4.3.21 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/10/xss-vulnerability-in-nextscripts-social-networks-auto-poster-plugin-impacts-100000-sites/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/social-networks-auto-poster-facebook-twitter-g/#developers");

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

if (version_is_less(version: version, test_version: "4.3.21")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.21", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
