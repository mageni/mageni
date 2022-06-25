###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zksoftware_webserver_default_credentials.nasl 39403 2014-07-21 13:37:20Z secpod$
#
# ZKSoftware WebServer Default Admin Credentials
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804475");
  script_version("$Revision: 11402 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-07-21 12:35:29 +0530 (Mon, 21 Jul 2014)");
  script_name("ZKSoftware WebServer Default Admin Credentials");

  script_tag(name:"summary", value:"This host is running ZKSoftware WebServer and it has default admin
  credentials.");
  script_tag(name:"vuldetect", value:"Send a crafted default admin credentials via HTTP POST request and check
  whether it is possible to login or not.");
  script_tag(name:"insight", value:"It was possible to login with default credentials.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to gain access to sensitive
  information or modify system configuration.");
  script_tag(name:"affected", value:"ZKSoftware WebServer");
  script_tag(name:"solution", value:"Change the default credentials.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_xref(name:"URL", value:"http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ZK_Web_Server/banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

kPort = get_http_port(default:80);

kBanner = get_http_banner(port: kPort);
if(!kBanner || "Server: ZK Web Server" >!< kBanner) exit(0);

host = http_host_name(port:kPort);

postdata = "username=administrator&userpwd=123456";
zkReq = string("POST /csl/check HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postdata), "\r\n\r\n",
                postdata);

zkRes = http_keepalive_send_recv(port:kPort, data:zkReq);

if(zkRes =~ "HTTP/1.. 200 OK"  && ">Department Name<" >< zkRes &&
   ">Privilege<" >< zkRes && ">Name<" >< zkRes)
{
   security_message(port:kPort);
   exit(0);
}

exit(99);
