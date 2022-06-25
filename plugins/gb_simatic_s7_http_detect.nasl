###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simatic_s7_http_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# Siemens SIMATIC S7 Device Detection (HTTP)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106098");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-15 17:03:46 +0700 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC S7 Device Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of Siemens SIMATIC S7
devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");


  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = '/Portal/Portal.mwsl?PriNav=Ident';
req = http_get(item:url, port:port);
res = http_keepalive_send_recv(port:port, data:req);

if ('alt="Siemens"'>< res && ('alt="Simatic Controller"></td>' >< res || 'Title_Area_Name">S7' >< res ||
                              "title>SIMATIC" >< res)) {
  mod = eregmatch(pattern: "<title>SIMATIC\&nbsp;([A-Z]+)?([0-9]+).*<\/title>", string: res);
  if (!isnull(mod[2]))
    model = mod[2];

  version = "unknown";
  x = 0;
  lines = split(res);

  foreach line (lines) {
    if ("Firmware:" >< line ) {
      ver = eregmatch(pattern: ">V.([^<]+)<", string: lines[x+1]);
      if (!isnull(ver[1])) {
        version = ver[1];
        break;
      }
      else {
        ver = eregmatch(pattern: ">V.([^<]+)<", string: lines[x+5]);
        if (!isnull(ver[1])) {
          version = ver[1];
          break;
        }
      }
    }
    x++;
  }

  x = 0;
  foreach line (lines) {
    if ("Order number" >< line) {
      module = eregmatch(pattern: ">([^<]+)", string: lines[x+1]);
      if (!isnull(module[1])) {
        set_kb_item(name: "simatic_s7/http/module", value: module[1]);
        break;
      }
    }
    x++;
  }

  module_type = eregmatch(pattern: 'moduleType">([^<]+)', string: res);
  if (!isnull(module_type[1]))
    set_kb_item(name: "simatic_s7/http/modtype", value: module_type[1]);

  set_kb_item(name: "simatic_s7/detected", value: TRUE);
  if (model)
    set_kb_item(name: "simatic_s7/http/model", value: model);
  if (version != "unknown")
    set_kb_item(name: "simatic_s7/http/" + port + "/version", value: version);
  set_kb_item(name: "simatic_s7/http/port", value: port);
}

exit(0);

