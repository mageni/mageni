##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_p1_wimax_modem_default_credentials_ua_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# P1 WiMAX Modem Default Credentials Unauthorized Access Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.802476");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-10-15 15:53:36 +0530 (Mon, 15 Oct 2012)");
  script_name("P1 WiMAX Modem Default Credentials Unauthorized Access Vulnerability");
  script_xref(name:"URL", value:"http://pastebin.com/pkuNfSJF");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2012/Oct/99");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"insight", value:"The flaw is due to the default configuration of the modem allows
anyone to access port 80 from the internet and modem is using the same
default login with 'admin' as the username and 'admin123' as the password.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host has P1 WiMAX Modem and is prone default credentials
unauthorized access vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to login
with default credentials and gain access to modem.");
  script_tag(name:"affected", value:"P1 WiMAX Modem");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)){
  exit(0);
}

host = http_host_name( port:port );

res = http_get_cache(item:"/login.php", port:port);

if(res =~ "HTTP/[0-9]\.[0-9] 200 .*" && "Server: lighttpd" >< res
   && "UI_ADMIN_USERNAME" >< res && "UI_ADMIN_PASSWORD" >< res)
{
  postdata = "UI_ADMIN_USERNAME=admin&UI_ADMIN_PASSWORD=admin123";
  req = string("POST /ajax.cgi?action=login HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", strlen(postdata), "\r\n",
               "\r\n", postdata);

  res = http_keepalive_send_recv(port:port, data:req);

  if( res =~ "HTTP/[0-9]\.[0-9] 200 .*" &&
     "location.href='index.php?sid=" >< res &&
     "Login Fail:" >!< res){
     security_message(port:port);
  }
}
