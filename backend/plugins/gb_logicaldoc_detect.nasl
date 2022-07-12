###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logicaldoc_detect.nasl 10922 2018-08-10 19:21:48Z cfischer $
#
# LogicalDOC Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140769");
  script_version("$Revision: 10922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 21:21:48 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-02-13 10:43:53 +0700 (Tue, 13 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("LogicalDOC Detection");

  script_tag(name:"summary", value:"Detection of LogicalDOC.

The script sends a connection request to the server and attempts to detect LogicalDOC.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.logicaldoc.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 443);

foreach dir (make_list_unique("/", "/logicaldoc", cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  names = make_list("frontend", "login");
  foreach name (names) {
    res = http_get_cache(port: port, item: dir + "/" + name + "/" + name + ".nocache.js");
    ub = eregmatch(pattern: ",Ub='([^']+)", string: res);
    if (isnull(ub[1]))
      continue;
    else {
      found_name = name;
      break;
    }
  }

  if (isnull(ub[1]))
    continue;

  url = dir + "/" + found_name + "/" + ub[1] + ".cache.html";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("logicaldoc" >< res) {
    # the version is retrieved via POST call to /login/info with a highly dynamic input computed in javascript
    # which we can't handle
    version = "unknown";

    set_kb_item(name: "logicalDOC/installed", value: TRUE);

    cpe = 'cpe:/a:logicaldoc:logicaldoc';

    register_product(cpe: cpe, location: install, port: port);

    log_message(data: build_detection_report(app: "LogicalDOC", version: version, install: install, cpe: cpe),
                port: port);
    exit(0);
  }
}

exit(0);
