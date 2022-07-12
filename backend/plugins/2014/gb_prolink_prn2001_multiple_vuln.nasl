###############################################################################
# OpenVAS Vulnerability Test
#
# Prolink PRN2001 Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.805021");
  script_version("2019-05-10T14:24:23+0000");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2019-05-10 14:24:23 +0000 (Fri, 10 May 2019)");
  script_tag(name:"creation_date", value:"2014-12-04 12:11:44 +0530 (Thu, 04 Dec 2014)");
  script_name("Prolink PRN2001 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is Prolink PRN2001 and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request
  and check whether it is able to login with default credentials");

  script_tag(name:"insight", value:"The Prolink PRN2001 is vulnerable to,

  - Incorrect User Management,

  - Exposure of Resource to Wrong Sphere.

  - Information Exposure,

  - Improper Neutralization of Script-Related HTML Tags in a Web Page (Basic XSS).

  - Denial of Service and

  - Security Misconfiguration.

  For more details about vulnerabilities please refer the reference links.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensiteve information, denial of service and
  execute arbitrary HTML and script code in a user's browser session in the
  context of an affected site.");

  script_tag(name:"affected", value:"Prolink PRN2001");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/35419");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("PRN2001/banner");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

http_port = get_http_port(default:8080);

banner = get_http_banner(port:http_port);

if(!banner || 'WWW-Authenticate: Basic realm="PRN2001"' >!< banner) exit(0);

host = http_host_name(port:http_port);

credential ="admin:password";
userpass = base64(str:credential );
req = 'GET / HTTP/1.1\r\n' +
      'Host: ' +  host + '\r\n' +
      'Authorization: Basic ' + userpass + '\r\n' +
      '\r\n';
res = http_keepalive_send_recv(port:http_port, data:req);

if(res =~ "^HTTP/1\.[01] 200"  && ">PROLiNK Wireless Router<" >< res)
{
  credential = str_replace( string:credential, find:":", replace:"/" );
  report = 'It was possible to login using the following credentials:\n\n' + credential;
  security_message(port:http_port, data:report);
  exit(0);
}

exit(99);
