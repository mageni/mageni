###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_camera_station_detect.nasl 11328 2018-09-11 12:32:47Z tpassfeld $
#
# Axis Camera Station Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.114027");
  script_version("$Revision: 11328 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-11 14:32:47 +0200 (Tue, 11 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-08-29 10:46:20 +0200 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axis Camera Station Detection");

  script_tag(name:"summary", value:"Detection of Axis Camera Station Web UI.

  The script sends a connection request to the server and attempts to detect the installation of Axis Camera Station.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.axis.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default: 80);
res1 = http_get_cache(port: port, item: "/axis-cgi/prod_brand_info/getbrand.cgi");

if('"Brand": "AXIS"' >< res1 && '"ProdFullName":' >< res1 && '"ProdFullName":' >< res1 && '"ProdNbr":' >< res1 && '"ProdType":' >< res1) {

  version = "unknown";
  install = "/";

  req = http_get_req(port: port, url: "/js/bootstrap.js", add_headers: make_array("Accept-Encoding", "gzip, deflate"));
  res2 = http_keepalive_send_recv(port: port, data: req);

  #version:"1.27.24.15"
  vers = eregmatch(pattern: 'version:"([0-9a-zA-Z.-]+)"', string: res2);

  if(vers[1]) version = vers[1];

  conclUrl = report_vuln_url(port: port, url: "/", url_only: TRUE);

  set_kb_item(name: "axis/camerastation/detected", value: TRUE);
  set_kb_item(name: "axis/camerastation/" + port + "/detected", value: TRUE);
  set_kb_item(name: "axis/camerastation/web/version", value: version);

  register_and_report_cpe(app: "Axis Camera Station", ver: version, base: "cpe:/a:axis:camera_station:", expr: "^([0-9a-zA-Z.-]+)", insloc: install, regPort: port, conclUrl: conclUrl);
}

exit(0);
