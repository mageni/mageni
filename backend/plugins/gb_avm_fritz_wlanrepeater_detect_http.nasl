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
  script_oid("1.3.6.1.4.1.25623.1.0.142675");
  script_version("2019-07-31T06:35:42+0000");
  script_tag(name:"last_modification", value:"2019-07-31 06:35:42 +0000 (Wed, 31 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-30 07:34:56 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("AVM FRITZ!WLAN Repeater Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of AVM FRITZ!WLAN Repeater.

  This script performs HTTP(S) based detection of AVM FRITZ!WLAN Repeater.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

fingerprint["90ba7e91583241a9939cbf70b6d74403"] = "1750E";
fingerprint["0c3d43bd179516d9c8609b93c7311709"] = "310";
fingerprint["72d41ed2fce5d8c0e117efff045c8d6c"] = "450E";

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

# nb: For some reasons some non-german devices contains a non-breaking space here which
# doesn't match our check below so we're just stripping it away.
res = str_replace(string: res, find: raw_string( 0xC2, 0xA0 ), replace: " ");
if ("FRITZ!WLAN Repeater" >< res &&
    ('"GUI_IS_REPEATER":true' >< res || "facNotAllowedOr10Min" >< res || "g_HelpWin" >< res)) {
  set_kb_item(name: "avm_fritz_wlanrepeater/detected", value: TRUE);
  set_kb_item(name: "avm_fritz_wlanrepeater/http/detected", value: TRUE);
  set_kb_item(name: "avm_fritz_wlanrepeater/http/port", value: port);

  model   = "unknown";
  version = "unknown";

  # "bluBarTitle": "FRITZ!WLAN Repeater 310"
  # "bluBarTitle":"FRITZ!WLAN Repeater 1750E"
  mod = eregmatch(pattern: '"bluBarTitle":[ ]?"FRITZ!WLAN Repeater ([^"]+)"', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "avm_fritz_wlanrepeater/http/" + port + "/concluded", value: mod[0]);
  }

  if (model == "unknown") {
    url = "/css/default/images/kopfbalken_mitte.gif";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);
    if (!isnull(res)) {
      md5 = hexstr(MD5(res));
      if(fingerprint[md5]) {
        model = fingerprint[md5];
        set_kb_item(name: "avm_fritz_wlanrepeater/http/" + port + "/concluded", value: url);
      }
    }
  }

  set_kb_item(name: "avm_fritz_wlanrepeater/http/" + port + "/model", value: model);
  set_kb_item(name: "avm_fritz_wlanrepeater/http/" + port + "/version", value: version);
}

exit(0);
