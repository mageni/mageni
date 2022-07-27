###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_network_camera_detect.nasl 11450 2018-09-18 10:48:31Z tpassfeld $
#
# Canon Network Camera Remote Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114031");
  script_version("$Revision: 11450 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-18 12:48:31 +0200 (Tue, 18 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-11 12:04:27 +0200 (Tue, 11 Sep 2018)");
  script_name("Canon Network Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  Canon Network Camera.

  This script sends HTTP GET request and try to ensure the presence of
  Canon network Camera.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/-wvhttp-01-/info.cgi";
res = http_get_cache(port: port, item: url);

if("The request requires user authentication." >< res || "Unauthorized" >< res) {
  url = "/";
  res = http_get_cache(port: port, item: url);
}

if("hardware:=" >< res || "type:=" >< res || "firmware:=" >< res || ('<a href="/viewer/admin/en/admin.html">Admin Viewer</a>' >< res && "Network Camera" >< res)) {

  version = "unknown";

  set_kb_item(name: "canon/network_camera/detected", value: TRUE);
  set_kb_item(name: "canon/network_camera/" + port + "/detected", value: TRUE);

  #firmware:=1.0.2
  ver = eregmatch(pattern: "firmware:=([Vv]er. )?([0-9.]+)", string: res);
  if(ver[2]) version = ver[2];

  set_kb_item(name: "canon/network_camera/version", value: version);

  #hardware:=Canon VB-M40
  mod = eregmatch(pattern: "hardware:=Canon ([a-zA-Z0-9-]+)|type:=Canon ([a-zA-Z0-9-]+)|Network Camera ([a-zA-Z0-9-]+)", string: res);
  if(mod[1]) model = mod[1];
  else if(mod[2]) model = mod[2];
  else if(mod[3]) model = mod[3];

  if(model) set_kb_item(name: "canon/network_camera/model", value: model);

  cpe = "cpe:/a:canon:network_camera:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Canon Network Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
