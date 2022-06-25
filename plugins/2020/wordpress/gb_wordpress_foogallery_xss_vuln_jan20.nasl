# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112686");
  script_version("2020-01-13T13:19:48+0000");
  script_tag(name:"last_modification", value:"2020-01-13 13:19:48 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-13 13:01:00 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-20182");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress FooGallery Plugin <= 1.8.18 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin FooGallery is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow an authenticated remote attacker
  to inject arbitrary script commands into an affected site.");

  script_tag(name:"affected", value:"WordPress FooGallery plugin through version 1.8.18.");

  script_tag(name:"solution", value:"No known solution is available as of 13th January, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/foogallery/#developers");
  script_xref(name:"URL", value:"https://medium.com/@Pablo0xSantiago/cve-2019-20182-foogallery-image-gallery-wordpress-plugin-1-8-12-stored-cross-site-scripting-d5864f1259f");

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

url = dir + "/wp-content/plugins/foogallery/README.txt";
res = http_get_cache(port: port, item: url);

if("=== FooGallery" >< res && "Changelog" >< res) {

  cl = eregmatch(pattern: "== Changelog.*", string: res);

  if(cl[0]) {
    vers = eregmatch(pattern: "= ([0-9.]+) =", string: cl[0]);

    if(vers[1] && version_is_less_equal(version: vers[1], test_version: "1.8.18")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "None Available", file_checked: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
