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
  script_oid("1.3.6.1.4.1.25623.1.0.114086");
  script_version("2019-03-21T12:19:01+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-03-21 12:19:01 +0000 (Thu, 21 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-20 13:52:50 +0100 (Wed, 20 Mar 2019)");
  script_name("Intellio Visus Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of
  Intellio Visus.

  This script sends HTTP GET request and try to ensure the presence of
  the web interface for Intellio Visus.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/index.html";

res = http_get_cache(port: port, item: url);

if("icam.login" >!< res || res !~ "[Ii]ntellio [Cc]amera [Ll]ogin") {
  url = "/login.html"; #Fallback-URL if the host uses this one instead.
  res = http_get_cache(port: port, item: url);

  if(res !~ "[Ii]ntellio [Cc]amera [Ll]ogin" || "window.onload = function()" >!< res
    || "<td>User:" >!< res || "<td>Password:" >!< res) {
    exit(0); #Software was not detected.
  }
}

#Version detection requires login.
version = "unknown";

set_kb_item(name: "intellio/visus/detected", value: TRUE);
set_kb_item(name: "intellio/visus/" + port + "/detected", value: TRUE);

cpe = "cpe:/a:intellio:visus:";

conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

register_and_report_cpe(app: "Intellio Visus",
                        ver: version,
                        base: cpe,
                        expr: "^([0-9.]+)",
                        insloc: "/",
                        regPort: port,
                        regService: "www",
                        conclUrl: conclUrl,
                        extra: "Version detection requires login.");

exit(0);
