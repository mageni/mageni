# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112680");
  script_version("2020-01-07T08:25:23+0000");
  script_tag(name:"last_modification", value:"2020-01-07 08:25:23 +0000 (Tue, 07 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-06 12:28:00 +0000 (Mon, 06 Jan 2020)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2019-19980", "CVE-2019-19981", "CVE-2019-19982", "CVE-2019-19984", "CVE-2019-19985");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Email Subscribers Plugin < 4.2.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Email Subscribers & Newsletters is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Unauthenticated file download with information disclosure

  - Blind SQL injection in INSERT statement

  - Insecure permissions on dashboard and settings

  - Cross-Site Request Forgery on Settings

  - Send test Emails from the administrative dashboard as an authenticated user");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities would allow an attacker
  to export subscriber lists and gain all of the information provided by subscribers, create a blind SQL injection,
  view and modify settings, along with editing email campaigns and subscriber lists, and modify settings via CSRF.");

  script_tag(name:"affected", value:"WordPress Email Subscribers & Newsletters plugin before version 4.2.3.");

  script_tag(name:"solution", value:"Update to version 4.2.3 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/email-subscribers/#developers");
  script_xref(name:"URL", value:"https://www.wordfence.com/blog/2019/11/multiple-vulnerabilities-patched-in-email-subscribers-newsletters-plugin/");

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

url = dir + "/wp-content/plugins/email-subscribers/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== Email Subscribers" >< res && "Changelog" >< res) {

  vers = eregmatch(pattern: "Stable tag: ([0-9.]+)", string: res);

  if(vers[1] && version_is_less(version: vers[1], test_version: "4.2.3")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "4.2.3", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
