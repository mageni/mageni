# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:wp-ecommerce:easy-wp-smtp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145070");
  script_version("2020-12-18T07:44:37+0000");
  script_tag(name:"last_modification", value:"2020-12-18 11:55:37 +0000 (Fri, 18 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-18 07:39:51 +0000 (Fri, 18 Dec 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-35234");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Easy WP SMTP Plugin < 1.4.4 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/easy-wp-smtp/detected");

  script_tag(name:"summary", value:"WordPress Easy WP SMTP Plugin is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The easy-wp-smtp plugin for WordPress allows Administrator account
  takeover, as exploited in the wild in December 2020. If an attacker can list the wp-content/plugins/easy-wp-smtp/
  directory, then they can discover a log file (such as #############_debug_log.txt) that contains all
  password-reset links. The attacker can request a reset of the Administrator password and then use a link found
  there.");

  script_tag(name:"affected", value:"WordPress Easy WP SMTP plugin prior to version 1.4.4.");

  script_tag(name:"solution", value:"Update to version 1.4.4 or later.");

  script_xref(name:"URL", value:"https://blog.nintechnet.com/wordpress-easy-wp-smtp-plugin-fixed-zero-day-vulnerability/");

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

if (version_is_less(version: version, test_version: "1.4.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.4.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit( 99 );
