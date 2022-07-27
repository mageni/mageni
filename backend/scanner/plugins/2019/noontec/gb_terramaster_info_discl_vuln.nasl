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

CPE = "cpe:/a:noontec:terramaster";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143072");
  script_version("2019-10-28T09:34:24+0000");
  script_tag(name:"last_modification", value:"2019-10-28 09:34:24 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-28 09:08:40 +0000 (Mon, 28 Oct 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2019-18385");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Terramaster Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_terramaster_nas_detect.nasl");
  script_mandatory_keys("terramaster_nas/detected");

  script_tag(name:"summary", value:"Terramaster NAS devices are prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"impact", value:"An unauthenticated attacker can download log files via the
  'include/makecvs.php?Event=' substring.");

  script_tag(name:"solution", value:"No known solution is available as of 28th October, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/gusrmsdlrh/CVE-Reserved3/blob/master/README.md");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = dir + "/include/makecvs.php?Event=http";

if (http_vuln_check(port: port, url: url, pattern: "Client-PORT", check_header: TRUE, extra_check: "Client-IP")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
