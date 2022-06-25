###############################################################################
# OpenVAS Vulnerability Test
#
# Moxa ioLogik Devices Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106359");
  script_version("2020-03-03T10:43:11+0000");
  script_tag(name:"last_modification", value:"2020-03-03 11:02:28 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2016-10-31 15:52:13 +0700 (Mon, 31 Oct 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa ioLogik Devices Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Moxa ioLogik devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80, 8080, 9090);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/01.htm");

if ("Server: ioLogik Web Server" >!< res)
  exit(0);

set_kb_item(name: "moxa/iologik/detected", value: TRUE);
set_kb_item(name: "moxa/iologik/http/port", value: port);

model = "unknown";
version = "unknown";
build = "unknown";

mo = eregmatch(pattern: "Model Name</TD>.*(E[0-9]{4})</TD>", string: res);
if (!isnull(mo[1]))
  model = mo[1];

ver = eregmatch(pattern: "Firmware Version</TD>.*V([0-9.]+)( Build([0-9]+))?", string: res);
if (!isnull(ver[1])) {
  version = ver[1];
  set_kb_item(name: "moxa/iologik/http/" + port + "/concluded", value: ver[0]);
}

if (!isnull(ver[3]))
  build = ver[3];

set_kb_item(name: "moxa/iologik/http/" + port + "/model", value: model);
set_kb_item(name: "moxa/iologik/http/" + port + "/version", value: version);
set_kb_item(name: "moxa/iologik/http/" + port + "/build", value: build);

exit(0);
