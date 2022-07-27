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
  script_oid("1.3.6.1.4.1.25623.1.0.112612");
  script_version("2019-07-22T13:14:48+0000");
  script_tag(name:"last_modification", value:"2019-07-22 13:14:48 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-22 12:36:00 +0000 (Mon, 22 Jul 2019)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2019-10673");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Ultimate Member Plugin < 2.0.40 CSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Ultimate Member is prone to a cross-site request forgery (CSRF) vulnerability.");

  script_tag(name:"insight", value:"The vulnerability exists because the attacker can change the e-mail address in the administrator profile
  which makes him able to reset the administrator password using the WordPress 'password forget' form.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a remote attacker
  to become admin and subsequently extract sensitive information and execute arbitrary code.");

  script_tag(name:"affected", value:"WordPress Ultimate Member plugin before version 2.0.40.");

  script_tag(name:"solution", value:"Update to version 2.0.40 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/ultimate-member/#developers");
  script_xref(name:"URL", value:"https://wpvulndb.com/vulnerabilities/9250");
  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/152315/WordPress-Ultimate-Member-2.0.38-Cross-Site-Request-Forgery.html");

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

url = dir + "/wp-content/plugins/ultimate-member/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== Ultimate Member" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "2.0.40")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.0.40", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
