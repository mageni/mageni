###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_typo3_select_image_xss_vuln.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# TYPO3 select_image.php Cross Site Scripting Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903230");
  script_version("$Revision: 13659 $");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2014-02-25 19:17:38 +0530 (Tue, 25 Feb 2014)");
  script_name("TYPO3 select_image.php Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_typo3_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TYPO3/installed");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/typo3-617-xss-disclosure-shell-upload");

  script_tag(name:"summary", value:"This host is installed with TYPO3 and is prone to cross site scripting
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it is able to read the
  cookie or not.");

  script_tag(name:"insight", value:"Flaw is due to improper validation of user-supplied input passed to
  'RTEtsConfigParams' parameter in 'select_image.php' page.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"TYPO3 6.1.7, previous versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("gvr_apps_auth_func.inc");

if(!typo_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:typo_port)){
  exit(0);
}

useragent = http_get_user_agent();
host = http_host_name(port:typo_port);
cookie = get_typo3_login_cookie(cinstall:dir, tport:typo_port, chost:host);

if(cookie){

  url = dir + '/typo3/sysext/rtehtmlarea/mod4/select_image.php?RTEtsConfigParams=<script>alert(document.cookie)</script>';
  req = string("GET ", url ," HTTP/1.1\r\n",
               "Host: ", host, "\r\n",
               "User-Agent: ", useragent, "\r\n",
               "Cookie: ", cookie, "\r\n\r\n");
  res = http_keepalive_send_recv(port:typo_port, data:req, bodyonly:FALSE);

  if(res =~ "^HTTP/1\.[01] 200" && "<script>alert(document.cookie)</script>" >< res){
    security_message(typo_port);
    exit(0);
  }
}
