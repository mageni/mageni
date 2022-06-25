###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hikvision_ip_camera_detect.nasl 12132 2018-10-26 14:29:51Z tpassfeld $
#
# Hikvision IP Camera Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.114037");
  script_version("$Revision: 12132 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 16:29:51 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-05 14:33:50 +0200 (Fri, 05 Oct 2018)");
  script_name("Hikvision IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8081);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of the
  Hikvision IP Camera web interface.

  This script sends HTTP GET request and try to ensure the presence of
  the Hikvision IP Camera web interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8081);

url = "/doc/script/config/system/channelDigital.js";
res = http_get_cache(port: port, item: url);

if("<u>The requested resource is not available.</u>" >< res || "Document Error: Not Found" >< res
  || "HTTP/1.1 404 Not Found" >< res) {
  url = "/doc/script/inc.js";
  res = http_get_cache(port: port, item: url);
}

if('"/hikvision://"' >< res || '{case"HIKVISION"' >< res) {

  version = "unknown";

  url2 = "/doc/script/global_config.js";
  res = http_get_cache(port: port, item: url2);
  if("<u>The requested resource is not available.</u>" >< res || "Document Error: Not Found" >< res
    || "HTTP/1.1 404 Not Found" >< res) {
    url2 = "/doc/script/lib/seajs/config/sea-config.js";
    res = http_get_cache(port: port, item: url2);
  }

  #seajs.web_version="V4.0.1build171121" #web_version:"3.1.3.131126" #web_version: "3.0.51.170214"
  ver = eregmatch(pattern: 'seajs.web_version\\s*=\\s*"V([0-9.]+)[a-zA-Z]+([0-9]+)"|web_version:\\s?"([0-9.]+)"', string: res);
  if(!isnull(ver[1]) && !isnull(ver[2])) version = ver[1] + "." + ver[2]; #Unifying the extracted versions for later use
  if(!isnull(ver[3])) version = ver[3];

  set_kb_item(name: "hikvision/ip_camera/detected", value: TRUE);
  set_kb_item(name: "hikvision/ip_camera/" + port + "/detected", value: TRUE);
  set_kb_item(name: "hikvision/ip_camera/version", value: version);

  cpe = "cpe:/a:hikvision:ip_camera:";

  conclUrl = report_vuln_url(port: port, url: url2, url_only: TRUE);

  register_and_report_cpe(app: "Hikvision IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.a-z]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
