###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oraclebi_discoverer_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# OracleBI Discoverer Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803130");
  script_version("$Revision: 10888 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-12-19 10:33:12 +0530 (Wed, 19 Dec 2012)");
  script_name("OracleBI Discoverer Version Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of OracleBI Discoverer.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");


  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

foreach dir (make_list_unique("/", "/discoverer" , cgi_dirs(port:port)))
{

  install = dir;
  if(dir == "/") dir = "";

  url =  dir + "/viewer";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

 if(">OracleBI Discoverer" >< res && ">Oracle Technology" >< res)
 {

   set_kb_item(name:"OracleBI Discoverer/installed", value:TRUE);
   ver = eregmatch(string: res, pattern: "Version ([0-9.]+)");
   if(ver[1])
   {
     set_kb_item(name: string("www/", port, "/OracleBIDiscoverer"), value: string(ver[1]," under ",install));
     set_kb_item(name:"OracleBIDiscoverer/installed", value:TRUE);

     cpe = build_cpe(value:ver[1], exp:"^([0-9.]+)", base:"cpe:/a:oracle:oraclebi_discoverer:");
     if(isnull(cpe))
       cpe = "cpe:/a:oracle:oraclebi_discoverer";

     register_product(cpe:cpe, location:install, port:port);
     log_message(data: build_detection_report(app:"OracleBI Discoverer",
                                              version:ver[1],
                                              install:install,
                                              cpe:cpe,
                                              concluded: ver[1]),
                                              port:port);

    }
  }
}
