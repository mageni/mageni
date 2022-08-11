# Copyright (C) 2019 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142502");
  script_version("2019-06-25T06:25:10+0000");
  script_tag(name:"last_modification", value:"2019-06-25 06:25:10 +0000 (Tue, 25 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 09:04:55 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-8229");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Multiple IP Cameras Configuration Download Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Multiple IP Cameras (e.g. Amcrest IPM-721S) are prone to an unauthenticated
  configuration file download vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The file /current_config/Sha1Account1 is accessible without authentication
  which contains unencrypted credentials.");

  script_tag(name:"impact", value:"An unauthenticated attacker may obtain sensitive information like admin
  credentials and use this for further attacks.");

  script_tag(name:"solution", value:"No known solution is available as of 25th June, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/ethanhunnt/IoT_vulnerabilities/blob/master/Amcrest_sec_issues.pdf");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_http_port(default: 80))
  exit(0);

res = http_get_cache(port: port, item: "/");

if (!res || "version=@WebVersion@" >!< res)
  exit(0);

url = "/current_config/Sha1Account1";

if (http_vuln_check(port: port, url: url, pattern: '"Password" : "', check_header: TRUE)) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
