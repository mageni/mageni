###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mesosphere_marathon_detect.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Mesosphere Marathon UI Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.114011");
  script_version("$Revision: 11328 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-07-20 11:00:14 +0200 (Fri, 20 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mesoshpere Marathon UI Detection");

  script_tag(name:"summary", value:"Detection of Mesosphere Marathon Web UI.

  The script sends a connection request to the server and attempts to detect Mesoshpere Marathon UI and to
  extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_xref(name:"URL", value:"https://mesosphere.github.io/marathon/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8080);
url = "/ui/main.js";
res = http_get_cache(port: port, item: url);

# marathon-ui - The web UI for Mesosphere's Marathon.
if("marathon-ui - The web UI for Mesosphere's Marathon." >< res ||
    'function(e,t){e.exports={name:"marathon-ui"' >< res) {
   version = "unknown";
   install = "/";

   vers = eregmatch(pattern: "version v([0-9.]+)", string: res);
   conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

   if(vers[1]) version = vers[1];

   set_kb_item(name: "mesosphere/marathon/detected", value: TRUE);
   set_kb_item(name: "mesosphere/marathon/version", value: version);
   set_kb_item(name: "mesosphere/marathon/" + port + "/detected", value: TRUE);

   cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:mesosphere:marathon:"); # CPE is not registered yet

   if(!cpe) cpe = 'cpe:/a:mesosphere:marathon';

   register_product(cpe: cpe, location: install, port: port);

   log_message(data: build_detection_report(app: "Mesosphere Marathon", version: version, install: install, cpe: cpe,
                                            concludedUrl: conclUrl),port: port);

}

exit(0);
