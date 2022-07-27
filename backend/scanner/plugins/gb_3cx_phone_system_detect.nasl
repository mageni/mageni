###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_3cx_phone_system_detect.nasl 10896 2018-08-10 13:24:05Z cfischer $
#
# 3CX Phone System Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140436");
  script_version("$Revision: 10896 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 15:24:05 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-10-18 13:56:42 +0700 (Wed, 18 Oct 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("3CX Phone System Detection");

  script_tag(name:"summary", value:"Detection of 3CX Phone System.

The script sends a connection request to the server and attempts to detect 3CX Phone System and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 5000, 5001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.3cx.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 5001);

res = http_get_cache(port: port, item: "/#/login");

if ("<title>3CX Phone System Management Console</title>" >< res && "public/app.js" >< res) {
  version = "unknown";

  url = "/public/app.js";
  req = http_get(port: port, item: url);
  # don't use http_keepalive_send_recv() since we won't get the whole data back
  res = http_send_recv(port: port, data: req);

  vers = eregmatch(pattern: '"version","([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "3cx_phone_system/version", value: version);
    concUrl = url;
  }

  set_kb_item(name: "3cx_phone_system/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:3cx:phone_system:");
  if (!cpe)
    cpe = 'cpe:/a:3cx:phone_system';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "3CX Phone System", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
