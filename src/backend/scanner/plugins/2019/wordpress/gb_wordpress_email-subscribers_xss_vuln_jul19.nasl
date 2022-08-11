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
  script_oid("1.3.6.1.4.1.25623.1.0.112620");
  script_version("2019-08-07T11:52:39+0000");
  script_tag(name:"last_modification", value:"2019-08-07 11:52:39 +0000 (Wed, 07 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-07 11:52:00 +0000 (Wed, 07 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-14364");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Email Subscribers Plugin < 4.1.7 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Email Subscribers & Newsletters is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a remote attacker
  to inject arbitrary JavaScript commands into an affected site.");

  script_tag(name:"affected", value:"WordPress Email Subscribers & Newsletters plugin before version 4.1.7.");

  script_tag(name:"solution", value:"Update to version 4.1.7 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/email-subscribers/#developers");
  script_xref(name:"URL", value:"https://github.com/ivoschyk-cs/CVE-s/blob/master/Email%20Subscribers%20%26%20Newsletters%20Wordpress%20Plugin%20(XSS)");

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

  if(vers[1] && version_is_less(version: vers[1], test_version: "4.1.7")) {
    report = report_fixed_ver(installed_version: vers[1], fixed_version: "4.1.7", file_checked: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
