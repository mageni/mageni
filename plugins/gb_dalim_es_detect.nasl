###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dalim_es_detect.nasl 10901 2018-08-10 14:09:57Z cfischer $
#
# DALIM ES Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.140292");
  script_version("$Revision: 10901 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:09:57 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2017-08-11 15:02:36 +0700 (Fri, 11 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DALIM ES Detection");

  script_tag(name:"summary", value:"Detection of DALIM ES.

The script sends a connection request to the server and attempts to detect DALIM ES and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.dalim.com/en/products/es-enterprise-solutions/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);

res = http_get_cache(port: port, item: "/Esprit/public/Login.jsp");

if ('dalimsoftware.png' >< res && "www.dalim.com" >< res) {
  version = "unknown";
  build = "unknown";

  res = http_get_cache(port: port, item: "/");

  # Major version
  vers = eregmatch(pattern: 'DALIM SOFTWARE GmbH</a></td><td class="table-context-cell table-context-info"><table class="table-info"><tr><td data-i18n="Version" class="table-info-label">version: </td><td class="table-info-value">([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "dalim_es/version", value: version);
  }

  req = http_get(port: port, item: "/build.html");
  res = http_keepalive_send_recv(port: port, data: req);

  bd = eregmatch(pattern: 'app-name">BUILD ([0-9.]+)', string: res);
  if (!isnull(bd[1])) {
    build = bd[1];
    set_kb_item(name: "dalim_es/build", value: build);
  }

  set_kb_item(name: "dalim_es/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dalim:es_core:");
  if (!cpe)
    cpe = 'cpe:/a:dalim:es_core';

  register_product(cpe: cpe, location: "/", port: port);

  log_message(data: build_detection_report(app: "DALIM ES", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], extra: "Build:    " + build),
              port: port);
  exit(0);
}

exit(0);
