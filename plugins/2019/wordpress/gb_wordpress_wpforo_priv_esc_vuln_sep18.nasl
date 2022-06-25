# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112294");
  script_version("2019-06-20T12:40:33+0000");
  script_tag(name:"last_modification", value:"2019-06-20 12:40:33 +0000 (Thu, 20 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-20 14:40:00 +0200 (Thu, 20 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2018-16613");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress wpForo Forum Plugin < 1.5.2 Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin wpForo Forum is prone to a privilege escalation vulnerability.");
  script_tag(name:"insight", value:"The plugin suffers from a privilege escalation vulnerability,
  whereby any registered forum user can escalate his privilege to become the forum administrator without any form of user interaction.");
  script_tag(name:"affected", value:"WordPress wpForo Forum plugin before version 1.5.2.");
  script_tag(name:"solution", value:"Update to version 1.5.2 or later.");

  script_xref(name:"URL", value:"https://github.com/9emin1/advisories/blob/master/wpForo-1-5-1.md");
  script_xref(name:"URL", value:"https://wpforo.com/community/wpforo-announcements/wpforo-1-5-2-is-released/");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wpforo/#developers");

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

url = dir + "/wp-content/plugins/wpforo/readme.txt";
res = http_get_cache(port: port, item: url);

if(("wpForo" >< res && "Forum" >< res) && "Changelog" >< res) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "1.5.2")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "1.5.2", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
