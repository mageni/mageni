###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_processmaker_detect.nasl 11439 2018-09-18 03:16:57Z ckuersteiner $
#
# ProcessMaker Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.141485");
  script_version("$Revision: 11439 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 05:16:57 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-18 09:15:36 +0700 (Tue, 18 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ProcessMaker Detection");

  script_tag(name:"summary", value:"Detection of ProcessMaker.

The script sends a connection request to the server and attempts to detect ProcessMaker and to extract its
version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.processmaker.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

foreach dir (make_list_unique("/sysworkflow", "/sys", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/en/neoclassic/login/login");

  if ("form[USR_PASSWORD_MASK]" >< res && "PM.js" >< res) {
    version = "unknown";

    url = "/jscore/src/PM.js";
    req = http_get(port: port, item: url);
    res = http_keepalive_send_recv(port: port, data: req);

    vers = eregmatch(pattern: "PM.version = '([0-9.]+)'", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = url;
    }

    set_kb_item(name: "processmaker/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:processmaker:processmaker:");
    if (!cpe)
      cpe = 'cpe:/a:processmaker:processmaker';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "ProcessMaker", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: concUrl),
                port: port);
    exit(0);
  }
}

exit(0);
