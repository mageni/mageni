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
  script_oid("1.3.6.1.4.1.25623.1.0.143195");
  script_version("2019-12-09T16:17:09+0000");
  script_tag(name:"last_modification", value:"2019-12-09 16:17:09 +0000 (Mon, 09 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-11-28 04:26:14 +0000 (Thu, 28 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Digitalisierungsbox Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of Digitalisierungsbox.

  The script sends a connection request to the server and attempts to detect Digitalisierungsbox.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 443, 8443, 4443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

url = "/cgi-bin/status.xml";
res = http_get_cache(port: port, item: url);

if ("Digitalisierungsbox" >!< res || "<sysName>" >!< res) {
  url = "/";
  res = http_get_cache(port: port, item: url);

  if ('title="Digitalisierungsbox' >!< res || "Env.setAppName" >!< res)
    exit(0);
}

version = "unknown";
model = "unknown";

set_kb_item(name: "digitalisierungsbox/detected", value: TRUE);
set_kb_item(name: "digitalisierungsbox/http/port", value: port);

mod = eregmatch(pattern: "Digitalisierungsbox (STANDARD|BASIC|SMART|PREMIUM)", string: res, icase: TRUE);
if (!isnull(mod[1]))
  model = mod[1];

# <firmware>11.01.02.102 from 2019/11/06 00:00:00</firmware>
vers = eregmatch(pattern: "<firmware>([0-9.]+)", string: res);
if (!isnull(vers[1])) {
  version = vers[1];
  set_kb_item(name: "digitalisierungsbox/http/" + port + "/concluded", value: vers[0]);
  set_kb_item(name: "digitalisierungsbox/http/" + port + "/concludedUrl",
              value: report_vuln_url(port: port, url: url, url_only: TRUE));
}

set_kb_item(name: "digitalisierungsbox/http/" + port + "/model", value: model);
set_kb_item(name: "digitalisierungsbox/http/" + port + "/version", value: version);

exit(0);
