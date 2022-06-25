# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.142076");
  script_version("$Revision: 14009 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:10:00 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-06 09:53:46 +0700 (Wed, 06 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo MySQL Web Interface Detection");

  script_tag(name:"summary", value:"Detection of Drobo MySQL Web Interface.

The script sends a connection request to the server and attempts to detect Drobo MySQL Web Interface.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/mysql/");

if ('appname">DroboApp' >< res && '/DroboAppsService.js' >< res && "></span> Start" >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/mysqlapp/detected", value: TRUE);
  set_kb_item(name: "drobo/mysqlapp/port", value: port);

  # This is actually part of CVE-2018-14696 so it might get fixed eventually
  url = '/mysql/api/drobo.php';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # "mModel":"Drobo 5N"
  model = eregmatch(pattern: '"mModel":"([^"]+)', string: res);
  if (!isnull(model[1]))
    set_kb_item(name: "drobo/mysqlapp/model", value: model[1]);
  # "mVersion":"3.5.16-8.109.96116"
  version = eregmatch(pattern: '"mVersion":"([^"]+)', string: res);
  if (!isnull(version[1])) {
    version = str_replace(string: version[1], find: " ", replace: "");
    version = str_replace(string: version, find: "[", replace: ".");
    version = str_replace(string: version, find: "]", replace: "");
    version = str_replace(string: version, find: "-", replace: ".");
    set_kb_item(name: "drobo/mysqlapp/fw_version", value: version);
  }
  # "mESAID":"drb163801a00166"
  esaid = eregmatch(pattern: '"mESAID":"([^"]+)', string: res);
  if (!isnull(esaid[1]))
    set_kb_item(name: "drobo/mysqlapp/esaid", value: esaid[1]);
}

exit(0);
