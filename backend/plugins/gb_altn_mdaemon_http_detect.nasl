# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113575");
  script_version("2021-02-09T01:24:28+0000");
  script_tag(name:"last_modification", value:"2021-02-09 11:23:12 +0000 (Tue, 09 Feb 2021)");
  script_tag(name:"creation_date", value:"2019-11-22 15:02:03 +0200 (Fri, 22 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Alt-N MDaemon Mail Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Alt-N MDaemon Mail Server.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ((res =~ "MDaemon[- ]Webmail" >< res || res =~ "Server\s*:\s*WDaemon") && "WorldClient.dll" >< res) {
  version = "unknown";

  set_kb_item(name: "altn/mdaemon/detected", value: TRUE);
  set_kb_item(name: "altn/mdaemon/http/detected", value: TRUE);
  set_kb_item(name: "altn/mdaemon/http/port", value: port);

  # "WorldClient/globals.min.js?v=20.0.3">
  vers = eregmatch(pattern: "\.js\?v=([0-9.]+)", string: res);
  if (isnull(vers[1])) {
    # MDaemon/WorldClient v9.5.1
    # MDaemon Email Server for Windows/WorldClient v16.5.4
    vers = eregmatch(pattern: "MDaemon.*v([0-9.]+)", string: res);
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "altn/mdaemon/http/" + port + "/concluded", value: vers[0]);
  }

  set_kb_item(name: "altn/mdaemon/http/" + port + "/version", value: version);
}

exit(0);
