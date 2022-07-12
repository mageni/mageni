###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dell_drac_default_login.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# Dell Remote Access Controller Default Login
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

CPE = 'cpe:/h:dell:remote_access_card';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103681");
  script_version("$Revision: 13659 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-03-18 17:03:03 +0100 (Mon, 18 Mar 2013)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Dell Remote Access Controller Default Login");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_dell_drac_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("dell_idrac/installed", "dell_idrac/generation");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"summary", value:"The remote Dell Remote Access Controller is prone to a default account
  authentication bypass vulnerability.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access to sensitive
  information or modify system configuration without requiring authentication.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

# TODO: check for iDRAC8
cpe_list = make_list("cpe:/a:dell:idrac4", "cpe:/a:dell:idrac5", "cpe:/a:dell:idrac6", "cpe:/a:dell:idrac7");

if (!infos = get_all_app_ports_from_list(cpe_list: cpe_list))
  exit(0);
port = infos['port'];

generation = get_kb_item("dell_idrac/generation");
if (!generation)
  exit(0);

function check_iDRAC_default_login(version) {
  user = 'root';
  pass = 'calvin';

  if (version == "4") {
    urls = make_list('/cgi/login');
    posts = make_list('user=' + user + '&hash=' + pass);
    login_success = make_list('top.location.replace("/cgi/main")');
  }

  else if (version == 5) {
    urls = make_list('/cgi-bin/webcgi/login');
    posts = make_list('user=' + user + '&password=' + pass);
    login_fail = '<RC>0x140004</RC>';
  }

  else if(version == 6 || version == 7) {
    urls = make_list('/data/login','/Applications/dellUI/RPC/WEBSES/create.asp');
    posts = make_list('user=' + user + '&password=' + pass, 'WEBVAR_PASSWORD=' + pass  + '&WEBVAR_USERNAME=' + user  + '&WEBVAR_ISCMCLOGIN=0');
    login_success = make_list('<authResult>0</authResult>',"'USERNAME' : 'root'");
  }

  else {
    return FALSE;
  }

  useragent = http_get_user_agent();
  host = http_host_name(port:port);

  foreach url (urls) {

    foreach post (posts) {

      buf = FALSE;

      sleep(1);

      len = strlen(post);

      req = string("POST ",url," HTTP/1.1\r\n",
                   "Host: ", host, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
                   "Accept-Language: en-us;q=0.5,en;q=0.3\r\n",
                   "Accept-Encoding: identity\r\n",
                   "Connection: keep-alive\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ",len,"\r\n",
                   "\r\n",
                   post);
      buf = http_send_recv(port:port, data:req);
      if(buf !~ "HTTP/1\.. 200") continue;

      if(login_fail && login_fail >!< buf) {
        return TRUE;
      }

      if(login_success) {
        foreach ls (login_success) {
          if(ls >< buf) {
            return TRUE;
          }
        }
      }
    }
  }
}

if(check_iDRAC_default_login(version:generation)) {
  message = 'It was possible to login with username "root" and password "calvin".\n';
  security_message(port:port, data:message);
  exit(0);
}

exit(99);
