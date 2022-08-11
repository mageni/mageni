###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wago_plc_http_detect.nasl 12700 2018-12-07 08:18:55Z ckuersteiner $
#
# WAGO PLC Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.141765");
  script_version("$Revision: 12700 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-07 09:18:55 +0100 (Fri, 07 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-07 09:16:51 +0700 (Fri, 07 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WAGO PLC Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of WAGO PLC Controllers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 443);

# 750 Series
res = http_get_cache(port: port, item: '/webserv/index.ssi');
if ("title> WAGO Ethernet Web-Based Management" >< res) {
  set_kb_item(name: "wago_plc/detected", value: TRUE);
  set_kb_item(name: "wago_plc/http/detected", value: TRUE);
  set_kb_item(name: "wago_plc/http/port", value: port);

  url = '/webserv/cplcfg/state.ssi';
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # <td>Order number </td>
  # <td> 750-841/000-000 </td>
  mod = eregmatch(pattern: "Order number </td>[^<]+<td> ([0-9-]+)", string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "wago_plc/http/" + port + "/model", value: mod[1]);

  # <td>Firmware revision </td>
  # <td> 01.05.15 (07) </td>
  vers = eregmatch(pattern: "Firmware revision </td>[^<]+<td> ([0-9.]+).\(([0-9]+)\)?", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    if (!isnull(vers[2]))
      version += '.' + vers[2];

    set_kb_item(name: "wago_plc/http/" + port + "/fw_version", value: version);
    set_kb_item(name: "wago_plc/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "wago_plc/http/" + port + "/concUrl", value: url);
  }

  # <td>Mac address </td>
  # <td> 0030DE0637EC </td>
  mac = eregmatch(pattern: "Mac address </td>[^<]+<td> ([0-9A-F]{12}) ", string: res);
  if (!isnull(mac[1])) {
    macaddr = tolower(substr(mac[1], 0, 1)) + ':' + tolower(substr(mac[1], 2, 3)) + ':' +
              tolower(substr(mac[1], 4, 5)) + ':' + tolower(substr(mac[1], 6, 7)) + ':' +
              tolower(substr(mac[1], 8, 9)) + ':' + tolower(substr(mac[1], 10, 11));
    set_kb_item(name: "wago_plc/http/" + port + "/mac", value: macaddr);
    register_host_detail(name: "MAC", value: macaddr, desc: "gb_wago_plc_http_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: macaddr);
  }

  exit(0);
}

# PFC 100/200
url = '/wbm/index.php';
res = http_get_cache(port: port, item: url);
if ("<title>WAGO Ethernet Web-based Management" >< res) {
  set_kb_item(name: "wago_plc/detected", value: TRUE);
  set_kb_item(name: "wago_plc/http/detected", value: TRUE);
  set_kb_item(name: "wago_plc/http/port", value: port);

  url = '/wbm/configtools.php';
  headers = make_array("Content-Type", "application/x-www-form-urlencoded",
                       "X-Requested-With", "XMLHttpRequest");
  data = '{"csrfToken":false,"renewSession":true,"aDeviceParams":{"0":{"name":"get_typelabel_value",' +
         '"parameter":["SYSDESC"],"sudo":true,"multiline":false,"timeout":12000,"dataId":0},"1":' +
         '{"name":"get_typelabel_value","parameter":["ORDER"],"sudo":true,"multiline":false,"timeout":12000,' +
         '"dataId":0},"2":{"name":"get_actual_eth_config","parameter":["X1","mac-address"],"sudo":true,' +
         '"multiline":false,"timeout":12000,"dataId":0},"3":{"name":"get_coupler_details","parameter":' +
         '["firmware-revision"],"sudo":true,"multiline":false,"timeout":12000,"dataId":0}}}';

  req = http_post_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

  # {"csrfToken":"","aDeviceResponse":[{"status":0,"resultString":"WAGO 750-8100 PFC100 CS 2ETH ECO","errorText":"","dataId":"0","callString":""},
  # {"status":0,"resultString":"750-8100","errorText":"","dataId":"0","callString":""},
  # {"status":0,"resultString":"00:30:de:42:6c:c7","errorText":"","dataId":"0","callString":""},
  # {"status":0,"resultString":"02.07.07(10)","errorText":"","dataId":"0","callString":""}]}
  mod = eregmatch(pattern: 'WAGO ([^"]+)', string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "wago_plc/http/" + port + "/model", value: mod[1]);

  vers = eregmatch(pattern: '"resultString":"([0-9.]+)\\(([0-9]+)\\)?', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    if (!isnull(vers[2]))
      version += '.' + vers[2];

    set_kb_item(name: "wago_plc/http/" + port + "/fw_version", value: version);
    set_kb_item(name: "wago_plc/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "wago_plc/http/" + port + "/concUrl", value: url);
  }

  mac = eregmatch(pattern: '"resultString":"([0-9a-f:]{17})"', string: res);
  if (!isnull(mac[1])) {
    set_kb_item(name: "wago_plc/http/" + port + "/mac", value: mac[1]);
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_wago_plc_http_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
  }

  exit(0);
}

# I/O-IPC
url = '/wbm/state.php';
res = http_get_cache(port: port, item: url);
if ("<title>WAGO Ethernet Web-Based Management" >< res) {
  set_kb_item(name: "wago_plc/detected", value: TRUE);
  set_kb_item(name: "wago_plc/http/detected", value: TRUE);
  set_kb_item(name: "wago_plc/http/port", value: port);

  # <td>Order Number</td>
  # <td>0758-0874-0000-0110</td>
  mod = eregmatch(pattern: "Order Number</td>[^<]+<td>([0-9-]+)", string: res);
  if (!isnull(mod[1]))
    set_kb_item(name: "wago_plc/http/" + port + "/model", value: mod[1]);

  # <td>Firmware Revision</td>
  # <td>01.02.30(09)</td>
  vers = eregmatch(pattern: "Firmware Revision</td>[^<]+<td>([0-9.]+)\(([0-9]+)\)?", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    if (!isnull(vers[2]))
      version += '.' + vers[2];

    set_kb_item(name: "wago_plc/http/" + port + "/fw_version", value: version);
    set_kb_item(name: "wago_plc/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "wago_plc/http/" + port + "/concUrl", value: url);
  }

  # <td>Mac Address</td>
  # <td>00:30:DE:FF:E2:72</td>
  mac = eregmatch(pattern: "Mac Address</td>[^<]+<td>([0-9A-F:]{17})", string: res);
  if (!isnull(mac[1])) {
    set_kb_item(name: "wago_plc/http/" + port + "/mac", value: tolower(mac[1]));
    register_host_detail(name: "MAC", value: tolower(mac[1]), desc: "gb_wago_plc_http_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: tolower(mac[1]));
  }

  exit(0);
}

exit(0);
