###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_archiva_detect.nasl 11407 2018-09-15 11:02:05Z cfischer $
#
# Apache Archiva Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100923");
  script_version("$Revision: 11407 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:02:05 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-12-01 13:10:27 +0100 (Wed, 01 Dec 2010)");
  script_name("Apache Archiva Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Apache Archiva.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default: 80);

res = http_get_cache(port: port, item: "/");

if ("<title>Apache Archiva" >!< res && "Archiva needs Javascript" >!< res) {
  res = http_get_cache(port: port, item: "/archiva/index.action");

  if ("<title>Apache Archiva" >!< res || "The Apache Software Foundation" >!< res || "Artifact ID" >!< res)
    exit(0);
  else
    install = "/archiva";
}
else
  install = "/";

version = "unknown";

if (install == "/") {
  url = '/restServices/archivaUiServices/runtimeInfoService/archivaRuntimeInfo/en';
  req = http_get_req(port: port, url: url,
                     add_headers: make_array("X-Requested-With", "XMLHttpRequest",
                                             "Accept", "application/json, text/javascript, */*; q=0.01"));
  res = http_keepalive_send_recv(port: port, data: req);

  vers = eregmatch(pattern: '"version":"([0-9.]+)",', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "apache_archiva/version", value: version);
  }
}
else {
  vers = eregmatch(string: res, pattern: ">Apache Archiva( |&nbsp;-&nbsp;)([0-9.]+[^<]+)<",icase: TRUE);
  if (!isnull(vers[2])) {
    version = vers[2];
    set_kb_item(name: "apache_archiva/version", value: version);
  }
}

set_kb_item(name: "apache_archiva/installed", value: TRUE);

cpe = build_cpe(value: version, exp: "^([0-9.A-Z-]+)", base: "cpe:/a:apache:archiva:");
if (!cpe)
  cpe = 'cpe:/a:apache:archiva';

register_product(cpe: cpe, location: install, port: port);

log_message(data: build_detection_report(app: "Apache Archiva", version: version, install: install, cpe: cpe,
                                         concluded: vers[0], concludedUrl: url),
            port: port);

exit(0);
