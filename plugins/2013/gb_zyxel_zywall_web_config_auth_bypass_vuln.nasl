##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zyxel_zywall_web_config_auth_bypass_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# ZyXEL ZyWALL Web Configurator Authentication Bypass Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.803199");
  script_version("$Revision: 11401 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-05-14 17:25:01 +0530 (Tue, 14 May 2013)");
  script_name("ZyXEL ZyWALL Web Configurator Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://dariusfreamon.wordpress.com/2013/05/12/sunday-shodan-defaults/");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("RomPager/banner");

  script_tag(name:"insight", value:"By default, ZyXEL ZyWALL installs with default user credentials
  (username/password combination). The web configurator account has a password of
  '1234', which is publicly known and documented. This allows remote attackers to
  trivially access the program or system and gain privileged access.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running ZyXEL ZyWALL Web Configurator and prone to
  authentication bypass vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain
  administrative access, circumventing existing authentication mechanisms.");
  script_tag(name:"affected", value:"ZyXEL ZyWALL");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("Server: RomPager" >!< banner){
  exit(0);
}

url = '/Forms/rpAuth_1';

postData = "LoginPassword=ZyXEL+ZyWALL+Series&hiddenPassword=ee11cbb19052" +
           "e40b07aac0ca060c23ee&Prestige_Login=Login";

host = http_host_name(port:port);

req = string("POST ", url, " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", strlen(postData), "\r\n",
             "\r\n", postData);

res = http_keepalive_send_recv(port:port, data:req);
if(res =~ "HTTP/1.. 303" && res =~ "Location:.*rpSys.html")
{
  security_message(port:port);
  exit(0);
}

exit(99);
