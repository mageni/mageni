# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112607");
  script_version("2019-07-16T19:08:46+0000");
  script_tag(name:"last_modification", value:"2019-07-16 19:08:46 +0000 (Tue, 16 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-16 19:00:00 +0000 (Tue, 16 Jul 2019)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ad Inserter Plugin < 2.4.22 Remote Code Execution Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Ad Inserter is prone to an authenticated remote code execution vulnerability.");

  script_tag(name:"insight", value:"The vulnerability stems from the use of the check_admin_referer() for authorization,
  when it was specifically designed to protect WordPress sites against cross-site request forgery (CSRF) exploits using nonces -
  one-time tokens used for blocking expired and repeated requests.

  Authenticated attackers who get their hands on a nonce can bypass the authorization checks powered by
  the check_admin_referer() function to access the debug mode provided by the Ad Inserter plugin.

  Once the attacker has a nonce at his disposal, he can immediately trigger the debugging feature and,
  even more dangerous, exploit the ad preview feature by sending a malicious payload containing arbitrary PHP code.");

  script_tag(name:"impact", value:"Successful exploitation would allow authenticated users (Subscribers and above)
  to execute arbitrary PHP code on websites using the plugin.");

  script_tag(name:"affected", value:"WordPress Ad Inserter plugin before version 2.4.22.");

  script_tag(name:"solution", value:"Update to version 2.4.22 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ad-inserter/#developers");
  script_xref(name:"URL", value:"https://www.bleepingcomputer.com/news/security/critical-bug-in-wordpress-plugin-lets-hackers-execute-code/");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2019/07/critical-vulnerability-patched-in-ad-inserter-plugin/");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/ad-inserter/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== Ad Inserter" >< res && "Changelog" >< res) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "2.4.22")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.4.22", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
