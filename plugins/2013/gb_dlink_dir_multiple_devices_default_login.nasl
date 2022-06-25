###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_multiple_devices_default_login.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# D-Link DIR Multiple Devices Default Login
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103690");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-04-09 11:03:03 +0100 (Tue, 09 Apr 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("D-Link DIR Multiple Devices Default Login");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dlink_dsl_detect.nasl", "gb_dlink_dap_detect.nasl", "gb_dlink_dir_detect.nasl", "gb_dlink_dwr_detect.nasl");
  script_mandatory_keys("Host/is_dlink_device"); # nb: Experiences in the past have shown that various different devices could be affected
  script_require_ports("Services/www", 80, 8080);

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote D-Link DIR device is prone to a default account
  authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration without requiring authentication.");

  script_tag(name:"affected", value:"All D-Link DIR devices. Other devices and models might be affected as well.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

CPE_PREFIX = "cpe:/o:d-link";

include("host_details.inc");
include("http_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe:CPE_PREFIX, service:"www", first_cpe_only:TRUE)) exit(0);

port = infos["port"];
CPE = infos["cpe"];

if(!dir = get_app_location(cpe:CPE, port:port)) exit(0);
if(dir == "/") dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:port);

username = "admin";
url = dir + "/session.cgi";

foreach pass (make_list("", "admin", "Admin", "password", "12345", "pass", "year2000", "private", "public")) {

  login = "REPORT_METHOD=xml&ACTION=login_plaintext&USER=" + username + "&PASSWD=" + pass + "&CAPTCHA=";
  len = strlen(login);

  req = string("POST ", url, " HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: identity\r\n",
               "Connection: keep-alive\r\n",
               "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
               "Referer: http://", host, "/setup.php\r\n",
               "Content-Length: 68\r\n",
               "Cookie: uid=g0C06BeyB7\r\n",
               "\r\n",
               login);
  recv = http_send_recv(port:port, data:req);
  if(recv =~ "HTTP/1.. (404|500)") exit(0);

  if("<RESULT>SUCCESS</RESULT>" >< recv) {
    if(strlen(pass) > 0)
      message = 'It was possible to login with username "admin" and password "' + pass + '".';
    else
      message = 'It was possible to login with username "admin" and an empty password.';
    security_message(port:port, data:message);
    exit(0);
  }
}

exit(99);