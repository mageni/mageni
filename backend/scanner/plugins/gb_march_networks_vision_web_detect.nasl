###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_march_networks_vision_web_detect.nasl 12218 2018-11-05 21:38:49Z tpassfeld $
#
# March Networks VisionWEB Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.114042");
  script_version("$Revision: 12218 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-05 22:38:49 +0100 (Mon, 05 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-05 18:28:04 +0100 (Mon, 05 Nov 2018)");
  script_name("March Networks VisionWEB Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installation of March
  Networks VisionWEB.

  This script sends HTTP GET request and try to ensure the presence of
  March Networks VisionWEB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 8001);

url = "/visionweb/index2.html";
res = http_get_cache(port: port, item: url);

if('<meta name="DESCRIPTION" content="VisionWEB. March Networks SpA' >< res && 'March Networks S.p.A."' >< res) {

  version = "unknown";

  set_kb_item(name: "march_networks/visionweb/detected", value: TRUE);
  set_kb_item(name: "march_networks/visonweb/" + port + "/detected", value: TRUE);

  #codebase="NettunoVisionWEB.cab#version=2,9,3814,1008"
  vers = eregmatch(pattern: 'codebase="NettunoVisionWEB.cab#version=([0-9]+),([0-9]+),([0-9]+),([0-9]+)"', string: res);
  if(!isnull(vers[1]) && !isnull(vers[2]) && !isnull(vers[3]) && !isnull(vers[4]))
    version = vers[1] + "." + vers[2] + "." + vers[3] + "." + vers[4];

  set_kb_item(name: "march_networks/visonweb/version", value: version);

  cpe = "cpe:/a:march_networks:visionweb:";

  conclUrl = report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "March Networks VisionWEB",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          conclUrl: conclUrl);
}

exit(0);
