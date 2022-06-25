###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_buffalo_airstation_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Buffalo AirStation Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140995");
  script_version("$Revision: 11021 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-04-18 13:00:04 +0700 (Wed, 18 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Buffalo AirStation Detection");

  script_tag(name:"summary", value:"Detection of Acrolinx.

The script sends a connection request to the server and attempts to detect Buffalo AirStation devices and to
extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.buffalo-technology.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/cgi-bin/cgi?req=twz");

if ('name="airstation_uname"' >< res && 'alt="BUFFALO"' >< res) {
  version = "unknown";

  url = '/cgi-bin/cgi?req=fnc&fnc=%24{get_json_param(DEVICE,1524028324602)}';
  header = make_array("X-Requested-With", "XMLHttpRequest",
                      "Content-type", "application/x-www-form-urlencoded");
  req = http_post_req(port: port, url: url, add_headers: header);
  res = http_keepalive_send_recv(port: port, data: req);
  vers = eregmatch(pattern: '"VERSION":"([0-9.]+)",', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = url;
  }

  mod = eregmatch(pattern: '"MODEL":"([^"]+)', string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "buffalo_airstation/model", value: model);
  }

  buf = eregmatch(pattern: '"SUB_VERSION":"([0-9.]+)', string: res);
  if (!isnull(buf[1]))
    extra += 'Sub Version:   ' + buf[1] + '\n';
  buf = eregmatch(pattern: '"BOOT_VERSION":"([0-9.-]+)', string: res);
  if (!isnull(buf[1]))
    extra += 'Boot Version:  ' + buf[1] + '\n';

  set_kb_item(name: "buffalo_airstation/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/o:buffalo:" + tolower(model) + "_firmware:");
  if (!cpe)
    cpe = "cpe:/o:buffalo:" + tolower(model) + "_firmware";

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "Buffalo Airstation " + model, version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
