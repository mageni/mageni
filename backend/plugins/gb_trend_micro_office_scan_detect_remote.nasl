###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_office_scan_detect_remote.nasl 14193 2019-03-14 15:07:17Z cfischer $
#
# Trend Micro OfficeScan Remote Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.811885");
  script_version("$Revision: 14193 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 16:07:17 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2017-11-02 17:15:23 +0530 (Thu, 02 Nov 2017)");
  script_name("Trend Micro OfficeScan Remote Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443, 4343);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version
  of Trend Micro OfficeScan.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default:4343);

req = http_get_req(port:port, url:"/officescan/console/html/help/webhelp/Preface.html");
res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "^HTTP/1\.[01] 200" && res =~ "<title>OfficeScan.*</title>" && "Trend Micro" >< res) {

  version = "unknown";

  MatchVerLine = egrep(pattern:"<title>OfficeScan.*</title>", string:res, icase:TRUE );
  if(MatchVerLine) {
    ver = eregmatch(pattern:' ([0-9.]+)([ SP0-9.]+)?', string:MatchVerLine);
    if(ver[2] && ver[1]) {
      version = ver[1] + ver[2];
    } else {
      version = ver[1];
    }
  }

  set_kb_item( name:"TrendMicro/OfficeScan/Installed/Remote", value:TRUE );
  cpe = build_cpe(value:version, exp:"^([0-9A-Z. ]+)", base:"cpe:/a:trendmicro:officescan:");
  if(!cpe)
    cpe = "cpe:/a:trendmicro:officescan";

  register_product(cpe:cpe, location:"/officescan", port:port, service:"www");

  log_message(data:build_detection_report(app:"Trend Micro OfficeScan",
                                          version:version,
                                          install:"/officescan",
                                          cpe:cpe,
                                          concluded:version),
                                          port:port);
}

exit(0);