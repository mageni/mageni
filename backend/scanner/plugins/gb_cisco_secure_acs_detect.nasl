###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_secure_acs_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# Cisco Secure Access Control Server Remote Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.813104");
  script_version("$Revision: 11021 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2018-03-28 16:13:37 +0530 (Wed, 28 Mar 2018)");
  script_name("Cisco Secure Access Control Server Remote Detection");

  script_tag(name:"summary", value:"Detection of running version of Cisco Secure
  Access Control Server.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

cisPort = get_http_port(default:443);

url = "/acsadmin/login.jsp";
res = http_get_cache(port:cisPort, item:url);

if("Server: ACS" >< res && res =~ "Location.*acsadmin")
{
  set_kb_item(name:"cisco/secure/acs/installed", value:TRUE);
  cookie = eregmatch(pattern:"Set-Cookie: JSESSIONID=([0-9A-Za-z]+);", string:res);
  if(cookie[1])
  {
    cookie = "JSESSIONID=" + cookie[1];
    req = http_get_req(port:cisPort, url:url, add_headers:make_array("Cookie", cookie));
    res = http_keepalive_send_recv(port:cisPort, data:req);

    if(">Cisco Secure ACS Login<" >< res && 'ProductName">Cisco Secure ACS' >< res)
    {
      version = eregmatch(pattern:"Version ([0-9.]+)", string:res);
      if(version[1]) {
        cisVer = version[1];
      }
    }
  }

  if(!cisVer)
  {
    req = http_get(item:"/", port:cisPort);
    res = http_keepalive_send_recv(port:cisPort, data:req);
    if("Server: ACS" >< res && "<title>ACS" >< res && "Cisco" >< res)
    {
      version = eregmatch(pattern:">Launch ACS ([0-9.]+)<", string:res);
      if(version[1]){
        cisVer = version[1];
      }
    }
  }
  if(cisVer)
  {
    set_kb_item(name: string("www/", cisPort, "/"), value: cisVer);
    cpe = build_cpe(value:cisVer, exp:"^([0-9.]+)", base:"cpe:/a:cisco:secure_access_control_server_solution_engine:");
    if(isnull(cpe))
      cpe = 'cpe:/a:cisco:secure_access_control_server_solution_engine';

    register_product(cpe:cpe, location:cisPort + '/tcp', port:cisPort);

    log_message(data: build_detection_report(app:"Cisco Secure Access Control Server", version:cisVer,
    install:cisPort + '/tcp', cpe:cpe, concluded:cisVer), port:cisPort);
    exit(0);
  }
}
exit(0);
