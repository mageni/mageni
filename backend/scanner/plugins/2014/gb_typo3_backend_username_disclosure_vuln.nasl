###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_backend_username_disclosure_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# TYPO3 Backend Username Disclosure Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804210");
  script_version("$Revision: 13659 $");
  script_bugtraq_id(49072);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-01-07 15:31:34 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 Backend Username Disclosure Vulnerability");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to obtain valid usernames.");
  script_tag(name:"vuldetect", value:"Send a Crafted HTTP POST request and check whether it is able to get sensitive
information.");
  script_tag(name:"insight", value:"An error exists in application, which returns a different response for
incorrect authentication attempts depending on whether or not the username
is incorrect");
  script_tag(name:"solution", value:"Upgrade to TYPO3 version 4.3.12, 4.4.9 or 4.5.4 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to username disclosure
vulnerability.");
  script_tag(name:"affected", value:"TYPO3 version before 4.3.11 and below, 4.4.8 and below, 4.5.3 and below");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45557/");
  script_xref(name:"URL", value:"http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-CORE-sa-2011-001");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("misc_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoLoca = get_app_location(cpe:CPE, port:typoPort))
{
  url = typoLoca + "/typo3/index.php";
  treq = http_get(item:string(url), port:typoPort);
  tres = http_send_recv(port:typoPort, data:treq, bodyonly:FALSE);

  username = urlencode(str:get_kb_item("http/login"));
  password = rand_str(length:10);

  if(!username)
    username = "admin";

  useragent = http_get_user_agent();
  host = http_host_name(port:typoPort);

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

      req = string("POST ",url," HTTP/1.0\r\n",
                   "Host: " + host + "\r\n",
                   "User-Agent: " + useragent + "\r\n",
                   "Referer: http://" + host + "/typo3/alt_menu.php \r\n",
                   "Connection: keep-alive\r\n",
                   "Cookie: ",cCookie,"\r\n",
                   "Content-Type: application/x-www-form-urlencoded\r\n",
                   "Content-Length: ",strlen(payload), "\r\n\r\n",
                   payload);
      buf = http_keepalive_send_recv(port:typoPort, data:req);

      if(buf && buf =~ "HTTP/1.. 200" && "Expires: 0" >< buf)
      {
        security_message(typoPort);
        exit(0);
      }
    }
  }
}
