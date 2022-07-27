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

CPE = "cpe:/a:facebook:official-facebook-pixel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112883");
  script_version("2021-04-13T13:41:23+0000");
  script_tag(name:"last_modification", value:"2021-04-14 10:27:53 +0000 (Wed, 14 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-13 11:24:11 +0000 (Tue, 13 Apr 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-24218");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Facebook for WordPress Plugin 3.0.x < 3.0.4 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wordpress_plugin_http_detect.nasl");
  script_mandatory_keys("wordpress/plugin/official-facebook-pixel/detected");

  script_tag(name:"summary", value:"The WordPress plugin Facebook for WordPress (formerly known as Official Facebook Pixel)
  is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The plugin contains a permission check in a specific function,
  blocking users lower than administrators from being able to access it, however, there is no nonce protection.
  This means that there is no verification that a request is coming from a legitimate authenticated administrator session.
  This makes it possible for attackers to craft a request that will be executed if they can trick an administrator
  into performing an action while authenticated to the target site.");

  script_tag(name:"impact", value:"The action could be used by an attacker to update the plugin's settings to point
  to their own Facebook Pixel console and steal metric data for a site. Worse yet, since there is no sanitization
  on the settings that are stored, an attacker could inject malicious JavaScript into the setting values.
  These values would then be reflected on the settings page, causing the code to execute in a site administrator's browser
  while accessing the settings page.

  Successful exploitation would allow an attacker to inject malicious backdoors into theme files or create
  new administrative user accounts that could be used for complete site takeover.");

  script_tag(name:"affected", value:"WordPress Facebook for WordPress plugin version 3.0.0 through 3.0.3.");

  script_tag(name:"solution", value:"Update to version 3.0.4 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/official-facebook-pixel/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2021/03/two-vulnerabilities-patched-in-facebook-for-wordpress-plugin/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if(version_in_range(version: version, test_version: "3.0.0", test_version2:"3.0.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
