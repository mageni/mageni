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
  script_oid("1.3.6.1.4.1.25623.1.0.112606");
  script_version("2019-07-12T10:32:23+0000");
  script_tag(name:"last_modification", value:"2019-07-12 10:32:23 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-12 10:27:00 +0000 (Fri, 12 Jul 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-5972", "CVE-2019-5973");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Online Lesson Booking Plugin < 0.8.7 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Online Lesson Booking is prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"An arbitrary script may be executed on the web browser of the user with the administrative privilege. - CVE-2019-5972

  If a user with the administrative privilege views a malicious page while logged in, unintended operations may be performed. - CVE-2019-5973");
  script_tag(name:"affected", value:"WordPress Online Lesson Booking plugin before version 0.8.7.");
  script_tag(name:"solution", value:"Update to version 0.8.7 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/online-lesson-booking-system/#developers");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN96988995/index.html");

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

url = dir + "/wp-content/plugins/online-lesson-booking-system/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== Online Lesson Booking ===" >< res && "Changelog" >< res) {

  vers = eregmatch( pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "0.8.7")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "0.8.7", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
