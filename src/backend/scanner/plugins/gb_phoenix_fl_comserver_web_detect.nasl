###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phoenix_fl_comserver_web_detect.nasl 11862 2018-10-12 09:37:18Z ckuersteiner $
#
# PHOENIX CONTACT FL COMSERVER Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140590");
  script_version("$Revision: 11862 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:37:18 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-08 12:30:46 +0700 (Fri, 08 Dec 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PHOENIX CONTACT FL COMSERVER Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of PHOENIX CONTACT FL COMSERVER devices.

The script sends a connection request to the server and attempts to detect PHOENIX CONTACT FL COMSERVER devices
and to extract its firmware version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.phoenixcontact.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/deviceinfo.htm";
res = http_get_cache(port: port, item: url);

if ('class="devicetyp">FL COMSERVER' >< res && "Phoenix Contact GmbH" >< res) {
  version = "unknown";

  mod = eregmatch(pattern: 'class="devicetyp">FL COMSERVER ([^<]+)', string: res);
  if (isnull(mod[1]))
    exit(0);

  model = mod[1];
  set_kb_item(name: "phoenix_comserver/model", value: model);

  vers = eregmatch(pattern: 'Firmware Version.*<p>.*E([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "phoenix_comserver/fw_version", value: version);
    concUrl = url;
  }

  mac = eregmatch(pattern: 'MAC Address.*([a-fA-F0-9:]{17})', string: res);
  if (!isnull(mac[1])) {
    extra = "Mac Address:   " + mac[1] + '\n';
    register_host_detail(name: "MAC", value: mac[1], desc: "gb_phoenix_fl_comserver_web_detect.nasl");
    replace_kb_item(name: "Host/mac_address", value: mac[1]);
  }

  set_kb_item(name: "phoenix_comserver/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:phoenixcontact:comserver_firmware:");
  if (!cpe)
    cpe = 'cpe:/o:phoenix_contact:comserver_firmware';

  register_product(cpe: cpe, install: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "PHOENIX CONTACT FL COMSERVER " + model, version: version,
                                           install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl,
                                           extra: extra),
              port: port);
  exit(0);
}

exit(0);
