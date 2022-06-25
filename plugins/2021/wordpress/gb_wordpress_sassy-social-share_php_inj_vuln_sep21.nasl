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

CPE = "cpe:/a:heateor:sassy_social_share";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.147078");
  script_version("2021-11-03T14:03:41+0000");
  script_tag(name:"last_modification", value:"2021-11-03 14:03:41 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-03 06:16:41 +0000 (Wed, 03 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-25 19:58:00 +0000 (Mon, 25 Oct 2021)");

  script_cve_id("CVE-2021-39321");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Sassy Social Share Plugin < 3.3.24 PHP Object Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/sassy-social-share/detected");

  script_tag(name:"summary", value:"The WordPress plugin Sassy Social Share is prone to a PHP
  Object injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Sassy Social Share WordPress plugin is vulnerable to PHP
  Object Injection via the wp_ajax_heateor_sss_import_config AJAX action due to deserialization of
  unvalidated user supplied inputs via the import_config function found in the
  ~/admin/class-sassy-social-share-admin.php file. This can be exploited by underprivileged
  authenticated users due to a missing capability check on the import_config function.");

  script_tag(name:"affected", value:"WordPress Sassy Social Share plugin through version 3.3.23.");

  script_tag(name:"solution", value:"Update to version 3.3.24 or later.");

  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/10/vulnerability-patched-in-sassy-social-share-plugin/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/sassy-social-share/#developers");

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

if (version_is_less(version: version, test_version: "3.3.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.24", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
