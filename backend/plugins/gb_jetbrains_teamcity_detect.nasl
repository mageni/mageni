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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114109");
  script_version("2019-07-15T14:18:50+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-15 14:18:50 +0000 (Mon, 15 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-15 15:03:33 +0200 (Mon, 15 Jul 2019)");

  script_name("JetBrains TeamCity Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  JetBrains TeamCity.

  This script sends an HTTP GET request and tries to ensure the presence of
  JetBrains TeamCity.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://www.jetbrains.com/teamcity/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/login.html";
res = http_get_cache(port: port, item: url);

if('content="TeamCity (Log in to TeamCity' >< res) {
  version = "unknown";

  #Version</span> 10.0.5
  ver = eregmatch(string: res, pattern: "Version</span> ([0-9.]+)", icase: TRUE);
  if(!isnull(ver[1]))
    version = ver[1];

  set_kb_item(name: "jetbrains/teamcity/detected", value: TRUE);

  cpe = "cpe:/a:jetbrains:teamcity:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "JetBrains TeamCity",
                          ver: version,
                          concluded: ver[0],
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl);
}

exit(0);
