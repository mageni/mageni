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
  script_oid("1.3.6.1.4.1.25623.1.0.112533");
  script_version("2019-03-29T09:25:06+0000");
  script_tag(name:"last_modification", value:"2019-03-29 09:25:06 +0000 (Fri, 29 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-06 11:54:00 +0100 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2018-19040", "CVE-2018-19041", "CVE-2018-19042", "CVE-2018-19043");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("WordPress Media File Manager Plugin <= 1.4.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin media-file-manager is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"WordPress media-file-manager plugin through version 1.4.2.");
  script_tag(name:"solution", value:"No known solution is available as of 06th March, 2019. Information regarding
  this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/media-file-manager/#developers");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/45809");

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

url = dir + "/wp-content/plugins/media-file-manager/readme.txt";
res = http_get_cache(port: port, item: url);

if("Media File Manager" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less_equal(version: vers[1], test_version: "1.4.2")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "NoneAvailable", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);