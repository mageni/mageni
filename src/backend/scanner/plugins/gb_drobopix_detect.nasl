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
  script_oid("1.3.6.1.4.1.25623.1.0.142110");
  script_version("$Revision: 14052 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 10:57:15 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-03-08 15:17:54 +0700 (Fri, 08 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Drobo DroboPix Detection");

  script_tag(name:"summary", value:"Detection of Drobo DroboPix.

The script sends a connection request to the server and attempts to detect Drobo DroboPix, s a one-click photo
upload solution for mobile devices on Drobo NAS devices.");

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

res = http_get_cache(port: port, item: "/DroboPix/");

if (">DroboApp</title>" >< res && "webui.drobopix" >< res) {
  set_kb_item(name: "drobo/nas/detected", value: TRUE);
  set_kb_item(name: "drobo/drobopix/detected", value: TRUE);
  set_kb_item(name: "drobo/drobopix/port", value: port);

  # This is actually part of CVE-2018-14702 so it might get fixed eventually
  url = '/DroboPix/api/drobo.php';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # "mModel":"Drobo 5N"
  model = eregmatch(pattern: '"mModel":"([^"]+)', string: res);
  if (!isnull(model[1]))
    set_kb_item(name: "drobo/drobopix/model", value: model[1]);
  # "mVersion":"3.5.16-8.109.96116"
  version = eregmatch(pattern: '"mVersion":"([^"]+)', string: res);
  if (!isnull(version[1])) {
    version = str_replace(string: version[1], find: " ", replace: "");
    version = str_replace(string: version, find: "[", replace: ".");
    version = str_replace(string: version, find: "]", replace: "");
    version = str_replace(string: version, find: "-", replace: ".");
    set_kb_item(name: "drobo/drobopix/fw_version", value: version);
  }
  # "mESAID":"drb163801a00166"
  esaid = eregmatch(pattern: '"mESAID":"([^"]+)', string: res);
  if (!isnull(esaid[1]))
    set_kb_item(name: "drobo/drobopix/esaid", value: esaid[1]);
}

exit(0);
