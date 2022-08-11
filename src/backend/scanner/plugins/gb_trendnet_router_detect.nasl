###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trendnet_router_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# TrendNet Router Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.107300");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-02-15 14:47:17 +0100 (Thu, 15 Feb 2018)");
  script_name("TrendNet Router Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to detect the
  presence of the router.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");

trdPort = get_http_port(default:8080);
res = http_get_cache(port:trdPort, item: "/");

if("Login to the" >< res && ("<title>TRENDNET | WIRELESS N ROUTER </title>" >< res || "<title>TRENDNET | WIRELESS N GIGABIT ROUTER </title>" >< res))
{
  model = "unknown";
  version = "unknown";
  install = trdPort + "/tcp";
  router= eregmatch(pattern: "Server: Linux, HTTP/1.., (TEW-[0-9a-zA-Z]+) Ver ([0-9.]+)", string: res);
  if (!isnull(router[1])) model = router[1];
  if (!isnull(router[2])) version = router[2];

  set_kb_item(name:"trendnet/detected", value:TRUE);
  set_kb_item(name:"trendnet/model", value:model);
  set_kb_item(name:"trendnet/version", value:version);
  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/h:trendnet:" + tolower(model) + ":");
  if (!cpe)
    cpe = 'cpe:/h:trendnet:' + tolower(model);


  register_product(cpe:cpe, location:install, port:trdPort);

  log_message(data: build_detection_report(app: "TrendNet Router " + model,
                                           version: version,
                                           install: install,
                                           cpe: cpe,
                                           concluded: router),
                                           port: trdPort);
  exit(0);
}
exit(0);
