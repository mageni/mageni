###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panasonic_ip_camera_detect.nasl 12234 2018-11-06 19:10:07Z tpassfeld $
#
# Panasonic IP Camera Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.114044");
  script_version("$Revision: 12234 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-06 20:10:07 +0100 (Tue, 06 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-05 22:37:25 +0100 (Mon, 05 Nov 2018)");
  script_name("Panasonic IP Camera Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of Panasonic's
  IP camera software.

  This script sends HTTP GET request and try to ensure the presence of
  Panasonic's IP camera software.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

url = "/admin/index.html?Language=0";
res = http_get_cache(port: port, item: url);

if(res =~ 'Basic realm="Panasonic [nN]etwork [dD]evice"') {

  #Only available after a successful login
  version = "unknown";
  model = "unknown";

  url2 = "/";
  res2 = http_get_cache(port: port, item: url2);

  #<title>WV-SPW631L Network Camera</title>
  #<title>WV-SPW631L Netzwerk-Kamera</title>
  mod = eregmatch(pattern: "(WV-[a-zA-Z0-9]+) (Network Camera|Netzwerk-Kamera)", string: res2);
  if(!isnull(mod[1])) model = mod[1];

  set_kb_item(name: "panasonic/ip_camera/detected", value: TRUE);
  set_kb_item(name: "panasonic/ip_camera/" + port + "/detected", value: TRUE);
  set_kb_item(name: "panasonic/ip_camera/model", value: model);
  cpe = "cpe:/a:panasonic:ip_camera:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Panasonic IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl,
                          extra: "Model: " + model + "; Note: Login required for version detection.");
}

exit(0);
