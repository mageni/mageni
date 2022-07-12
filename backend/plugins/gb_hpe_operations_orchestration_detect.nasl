###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_operations_orchestration_detect.nasl 11408 2018-09-15 11:35:21Z cfischer $
#
# HPE Operations Orchestration Remote Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.813101");
  script_version("$Revision: 11408 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 13:35:21 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-03-26 17:54:51 +0530 (Mon, 26 Mar 2018)");
  script_name("HPE Operations Orchestration Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of HPE Operations
  Orchestration.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080, 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

hpePort = get_http_port(default:8080);

res = http_get_cache(port:hpePort, item:"/oo/");
if((">HPE Operations Orchestration<" >< res && "Server: OO" >< res)||
   ("Server: OO" >< res && res =~ "Location.*oo/login/login-form" && "302 Found" >< res))
{
  set_kb_item(name:"hpe/operations/orchestration/installed", value:TRUE);

  req = http_get(item:"/oo/rest/latest/version", port:hpePort);
  res = http_keepalive_send_recv(port:hpePort, data:req);
  if(res =~ "HTTP/1.. 200 OK" && '"version"' >< res && '"revision"' >< res && '"build' >< res)
  {
    ##version":"10.60 - Community Edition","revision":"c0304cf4577137dfd63bcc7edbc7517763fa14aa",
    ##"build ID":"27","build number":"27","build job name":"10"
    version = eregmatch(pattern:'"version":"([0-9.]+)', string:res);
    if(version[1]){
      hpeVer = version[1];
    }
  }
  else
  {
    url1 = "/online-help/Content";
    foreach url2(make_list("/_HPc_HomePage_HPE_SW.htm", "/HelpCenter_Home.htm"))
    {
      url = url1 + url2 ;
      req = http_get(item: url, port:hpePort);
      res = http_keepalive_send_recv(port:hpePort, data:req);
      if(res =~ "HTTP/1.. 200 OK" && 'productName="Operations Orchestration' >< res && "Help Center" >< res &&
        res =~ "topicTitle.*Operations Orchestration")
      {
        ##productName="Operations Orchestration" productVersion="10.70"
        version = eregmatch(pattern:'productVersion="([0-9.]+)"', string:res);
        if(version[1])
        {
          hpeVer = version[1];
          break;
        }
      }
    }
  }

  if(hpeVer)
  {
    set_kb_item(name: string("www/", hpePort, "/oo"), value: hpeVer);
    cpe = build_cpe(value:hpeVer, exp:"^([0-9.]+)", base:"cpe:/a:hp:operations_orchestration:");
    if(isnull(cpe))
      cpe = 'cpe:/a:hp:operations_orchestration';

    register_product(cpe:cpe, location:hpePort + '/tcp', port:hpePort);

    log_message(data: build_detection_report(app:"HPE Operations Orchestration", version:hpeVer,
    install:hpePort + '/tcp', cpe:cpe, concluded:hpeVer), port:hpePort);
    exit(0);
  }
}
exit(0);
