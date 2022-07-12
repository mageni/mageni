###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_webcenter_content_detect.nasl 11418 2018-09-17 05:57:41Z cfischer $
#
# Oracle WebCenter Content Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811709");
  script_version("$Revision: 11418 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 07:57:41 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-08-18 12:44:35 +0530 (Fri, 18 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Oracle WebCenter Content Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Oracle WebCenter Content.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("cpe.inc");

owPort = get_http_port(default:80);

sndReq = http_get(item:"/cs/login/login.htm", port:owPort);
rcvRes = http_keepalive_send_recv(port:owPort, data:sndReq);

if(rcvRes && ">Oracle WebCenter Content Sign In<" >< rcvRes &&
   (rcvRes =~ "Copyright.*Oracle") || ("ORACLETEXTSEARCH" >< rcvRes && "ORACLE_QUERY_OPTIMIZER" >< rcvRes))
{
  owVer = "unknown";
  version = "unknown";
  version_url = "/_ocsh/help/state?navSetId=help_for_translation_MA_user_en_MA" +
                "_user_html_l10n_adtuh_hlpbk&navId=1";

  sndReq = http_get(item:version_url, port:owPort);
  rcvRes = http_keepalive_send_recv(port:owPort, data:sndReq);

  if(rcvRes =~ "HTTP/1.. 302" && "Location: http" >< rcvRes)
  {
    newverUrl =  eregmatch(pattern:"Location: (http.*&destination=)", string:rcvRes);
    newverUrl = newverUrl[1];
    if(newverUrl)
    {
      sndReq = http_get(item:newverUrl, port:owPort);
      rcvRes = http_keepalive_send_recv(port:owPort, data:sndReq);
    }
  }

  if(rcvRes =~ "HTTP/1.. 200 OK" && "Oracle WebCenter Content Help<" >< rcvRes &&
  ("Dynamic Converter Online Help" >< rcvRes || "Dynamic Converter<" >< rcvRes))
  {
    version = eregmatch( pattern:"([0-9A-Za-z]+) ([A-Za-z]+ [0-9]+ )?\(([0-9.]+)\) - Oracle WebCenter Content Help</title>", string:rcvRes);
    if(version[2] && version[1] && version[3])
    {
      owVer = version[3];
      version = version[1] + " " + version[2] + owVer ;
    } else if(version[3] && version[1])
    {
      owVer = version[3];
      version = version[1] + " " + owVer ;
    }
    if(owVer){
      set_kb_item(name:"Oracle/WebCenter/Content/Version", value:owVer);
    }
  }

  set_kb_item(name:"Oracle/WebCenter/Content/Installed", value:TRUE);

  cpe = build_cpe(value:owVer, exp:"^([0-9.]+)", base:"cpe:/a:oracle:webcenter_content:");
  if(!cpe)
    cpe = 'cpe:/a:oracle:webcenter_content';

  register_product(cpe:cpe, location:"/", port:owPort);
  log_message(data: build_detection_report(app: "Oracle WebCenter Content",
                                           version:owVer,
                                           install:"/",
                                           cpe:cpe,
                                           concluded:version),
                                           port:owPort);
  exit(0);
}
exit(0);
