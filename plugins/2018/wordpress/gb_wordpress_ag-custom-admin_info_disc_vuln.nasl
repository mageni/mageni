###############################################################################
# OpenVAS Vulnerability Test
#
# WordPress Absolutely Glamorous Custom Admin Plugin <= 6.4.1 Database Backup Arbitrary File Download Vulnerability
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112439");
  script_version("2019-05-13T12:30:25+0000");
  script_tag(name:"last_modification", value:"2019-05-13 12:30:25 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2018-11-26 13:10:00 +0100 (Mon, 26 Nov 2018)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress Absolutely Glamorous Custom Admin Plugin <= 6.4.1 Database Backup Arbitrary File Download Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"WordPress Absolutely Glamorous Custom Admin plugin is prone to an information
	disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"WordPress Absolutely Glamorous Custom Admin plugin through version 6.4.1.");

  script_tag(name:"solution", value:"No known solution is available as of 13th May, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://cxsecurity.com/issue/WLB-2018110141");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/ag-custom-admin/#developers");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

CPE = "cpe:/a:wordpress:wordpress";

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/ag-custom-admin/readme.txt";
res = http_get_cache(port: port, item: url);

if(res =~ "=== (Absolutely Glamorous|AG) Custom Admin" && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if(!isnull(vers[1]) && version_is_less_equal(version: vers[1], test_version: "6.4.1")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "None");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
