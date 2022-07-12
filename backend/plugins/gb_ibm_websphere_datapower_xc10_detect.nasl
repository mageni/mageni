###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_datapower_xc10_detect.nasl 10888 2018-08-10 12:08:02Z cfischer $
#
# IBM WebSphere DataPower XC10 Appliance Version Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.808183");
  script_version("$Revision: 10888 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:08:02 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2016-07-05 13:49:16 +0530 (Tue, 05 Jul 2016)");
  script_name("IBM WebSphere DataPower XC10 Appliance Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  IBM WebSphere DataPower XC10 Appliance.

  This script sends HTTP GET request and try to login via default credentials
  and fetches the version.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("IBM_WebSphere/banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("smtp_func.inc");

xc_port = get_http_port(default:80);

host = http_host_name(port:xc_port);

banner = get_http_banner(port:xc_port);

if('Server: IBM WebSphere' >!< banner){
 exit(0);
}

##login with default credentilas to check version
post_data = "zeroUserName=xcadmin&zeroPassword=xcadmin&postLoginTargetURI=%2Fdashboard%2F";

req = 'POST /login HTTP/1.1\r\n' +
      'Host: '+host+'\r\n' +
      'Content-Type: application/x-www-form-urlencoded\r\n'+
      'Content-Length: 76\r\n' +
      '\r\n' +
      post_data;
res = http_keepalive_send_recv(port:xc_port, data:req);

if('Server: IBM WebSphere' >!< res && res =~ "HTTP/1.. 302"){
 exit(0);
}

if(!url[0]  = eregmatch(pattern:"Pzcsrf=([0-9a-zA-Z]+)", string:res)){
  exit(0);
}
if(!cookie[1] = eregmatch(pattern:"zsessionid=([0-9a-zA-Z]+);", string:res)){
  exit(0);
}
if(!cookie1[1] = eregmatch(pattern:"pzerocsrfprotectsec=(.*)==;", string:res)){
  exit(0);
}

url = '/dashboard/welcome/?'+url[0];

##SEnd request and receive response
req2 = 'GET ' + url +' HTTP/1.1\r\n' +
       'Host: '+host+'\r\n' +
       'Cookie: zsessionid='+cookie[1]+ '; pzerocsrfprotectsec=' +cookie1[1]+ '\r\n'+
       '\r\n';
res2 = http_keepalive_send_recv(port:xc_port, data:req2);

if(">IBM WebSphere DataPower XC10 Appliance<" >< res2 && res2 =~ "HTTP/1.. 200 OK" &&
   ">Dynamic Cache<" >< res2 && ">Simple Data Grid<" >< res2 && ">Log Out" >< res2)
{
  version = eregmatch(pattern:"> ([0-9.]+).*VMware Virtual Platform <", string:res2);
  if(version[1]){
    version = version[1];
  }
  else{
    version = "Unknown";
  }

  set_kb_item(name:"IBM/Websphere/Datapower/XC10/Version", value:version);
  set_kb_item( name:"IBM/Websphere/Datapower/XC10/installed", value:TRUE);

  cpe = build_cpe(value:version, exp:"([0-9.]+)", base:"cpe:/h:ibm:websphere_datapower_xc10_appliance:");
  if(isnull(cpe))
    cpe = "cpe:/h:ibm:websphere_datapower_xc10_appliance";

  register_product(cpe:cpe, location:'/', port:xc_port);
  log_message(data: build_detection_report(app:"IBM WebSphere DataPower XC10 Appliance",
                                            version:version,
                                            install: '/',
                                            cpe:cpe,
                                            concluded:version),
                                            port:xc_port);
  exit(0);
}
