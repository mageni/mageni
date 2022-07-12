###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sonos_detect.nasl 10915 2018-08-10 15:50:57Z cfischer $
#
# Sonos Speaker Detection
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141019");
  script_version("$Revision: 10915 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:50:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-04-24 09:33:03 +0700 (Tue, 24 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sonos Speaker Detection");

  script_tag(name:"summary", value:"Detection of Sonos Speaker.

The script sends a connection request to the server and attempts to detect Sonos Speaker and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 1400);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.sonos.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 1400);

banner = get_http_banner(port: port);

if (banner !~ "Linux UPnP.*Sonos/")
  exit(0);

url = '/xml/device_description.xml';
req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

if ("<modelName>" >!< res)
  exit(0);

mod = eregmatch(pattern: "<modelName>([^<]+)", string: res);
if (!isnull(mod[1]))
  model = mod[1];

version = "unknown";
# <softwareVersion>42.2-51240</softwareVersion>
vers = eregmatch(pattern: "<softwareVersion>([^<]+)", string: res);
if (!isnull(vers[1])) {
  version = str_replace(string: vers[1], find: "-", replace: ".");
  concUrl = url;
}

# <hardwareVersion>1.8.3.7-2</hardwareVersion>
hw_vers = eregmatch(pattern: "<hardwareVersion>([^<]+)", string: res);
if (!isnull(hw_vers[1]))
  extra = "Hardware Version:   " + hw_vers[1];

set_kb_item(name: "sonos_speaker/detected", value: TRUE);

tmp_mod = tolower(ereg_replace(string: model, pattern: "[ :]", replace: "_"));
cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:sonos:" + tmp_mod + ":");
if (!cpe)
  cpe = "cpe:/a:sonos:" + tmp_mod;

register_product(cpe: cpe, location: "/", port: port, service: "www");

log_message(data: build_detection_report(app: "Sonos Speaker " + model, version: version, install: "/", cpe: cpe,
                                         concluded: vers[0], concludedUrl: concUrl, extra: extra),
            port: port);

exit(0);
