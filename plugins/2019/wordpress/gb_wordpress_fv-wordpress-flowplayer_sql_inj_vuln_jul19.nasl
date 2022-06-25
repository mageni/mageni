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
  script_oid("1.3.6.1.4.1.25623.1.0.112608");
  script_version("2019-07-18T11:05:23+0000");
  script_tag(name:"last_modification", value:"2019-07-18 11:05:23 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-18 10:43:00 +0000 (Thu, 18 Jul 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-13573");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress FV Flowplayer Video Player Plugin < 7.3.19.727 SQL Injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin FV Flowplayer is prone to an SQL injection vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a remote attacker
  to execute arbitrary SQL commands on the affected system.");

  script_tag(name:"affected", value:"WordPress FV Flowplayer plugin before version 7.3.19.727.");

  script_tag(name:"solution", value:"Update to version 7.3.19.727 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/fv-wordpress-flowplayer/#developers");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/FG-VD-19-097");
  script_xref(name:"URL", value:"https://plugins.trac.wordpress.org/changeset/2121566/fv-wordpress-flowplayer/trunk/models/db.php");

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

url = dir + "/wp-content/plugins/fv-wordpress-flowplayer/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== FV " >< res && "Flowplayer" >< res && "Changelog" >< res) {

  cl = eregmatch(pattern: "== Changelog.*", string: res);

  if(cl[0]) {
    vers = eregmatch(pattern: "= ([0-9.]+) ", string: cl[0]);

    if(vers[1] && version_is_less(version: vers[1], test_version: "7.3.19.727")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "7.3.19.727", file_checked: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
