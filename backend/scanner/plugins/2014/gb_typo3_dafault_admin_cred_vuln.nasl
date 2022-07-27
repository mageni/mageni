###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_dafault_admin_cred_vuln.nasl 2014-01-10 13:11:49Z jan$
#
# TYPO3 Default Admin Credentials
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804223");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-01-10 13:11:49 +0530 (Fri, 10 Jan 2014)");
  script_name("TYPO3 Default Admin Credentials");

  script_xref(name:"URL", value:"http://wiki.typo3.org/TYPO3_Installation_Basics");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to access the program
  or system and gain privileged access.");

  script_tag(name:"vuldetect", value:"Login to backend login with default credentials.");

  script_tag(name:"insight", value:"TYPO3 installs with default admin credentials (admin/password).");

  script_tag(name:"solution", value:"After installation change all default installed accounts to use a unique
  and secure password. Please see the references for more information.");

  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and it has default admin credentials.");

  script_tag(name:"affected", value:"All TYPO3 version's which gets installed with default credentials.");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

function get_typo3_login(cinstall, tport, chost)
{
  url = cinstall + "/typo3/index.php";
  treq = http_get(item:string(url), port:tport);
  tres = http_send_recv(port:tport, data:treq, bodyonly:FALSE);

  username = "admin";
  password = "password";

  challenge = eregmatch(pattern:'name="challenge" value="([a-z0-9]+)"' , string:tres);

  if(challenge)
  {
    password = hexstr(MD5(password));
    userident = hexstr(MD5(username + ":" + password + ":" + challenge[1]));
    payload = "login_status=login&username=" + username + "&p_field=&commandLI=Log+In&" +
              "userident=" + userident + "&challenge=" + challenge[1] + "&redirect_url=" +
              "alt_main.php&loginRefresh=&interface=backend";

    tcookie = eregmatch(pattern:"(be_typo_user=[a-z0-9]+\;)" , string:tres);
    PHPSESSID = eregmatch(pattern:"(PHPSESSID=[a-z0-9]+\;?)" , string:tres);

    if(!PHPSESSID[1])
      PHPSESSID[1] = "PHPSESSID=37dh7b4vkprsui40hmg3hf4716";

    if (tcookie[1] && PHPSESSID[1])
    {
      cCookie = tcookie[1] + ' showRefMsg=false; ' + PHPSESSID[1] + " typo3-login-cookiecheck=true";

      useragent = http_get_user_agent();
      req = string("POST ", url, " HTTP/1.1\r\n",
                   "Host: ", chost, "\r\n",
                   "User-Agent: ", useragent, "\r\n",
                   "Referer: http://" + chost + "/typo3/alt_menu.php \r\n",
                   "Connection: keep-alive\r\n",
                   "Cookie: ",cCookie,"\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ",strlen(payload), "\r\n\r\n",
                   payload);
      buf = http_keepalive_send_recv(port:tport, data:req);

      if(buf)
      {
        pat = "Location:.*(backend|alt_main)\.php";
        page = eregmatch(pattern:pat, string:buf);

        if(page)
        {
          security_message(port:tport);
          exit(0);
        }
      }
    }
  }
}

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoLoca = get_app_location(cpe:CPE, port:typoPort))
{
  host = http_host_name(port:typoPort);
  get_typo3_login(cinstall: typoLoca, tport:typoPort, chost:host);
}
