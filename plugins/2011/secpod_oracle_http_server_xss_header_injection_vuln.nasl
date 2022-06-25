###############################################################################
# OpenVAS Vulnerability Test
#
# Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902526");
  script_version("2019-05-17T12:32:34+0000");
  script_tag(name:"last_modification", value:"2019-05-17 12:32:34 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Oracle HTTP Server 'Expect' Header Cross-Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17393/");
  script_xref(name:"URL", value:"http://www.securiteam.com/securityreviews/5KP0M1FJ5E.html");
  script_xref(name:"URL", value:"http://www.yaboukir.com/wp-content/bugtraq/XSS_Header_Injection_in_OHS_by_Yasser.pdf");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Oracle-Application-or-HTTP-Server/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in context of an affected site.");

  script_tag(name:"affected", value:"Oracle HTTP Server for Oracle Application Server 10g Release 2.");

  script_tag(name:"insight", value:"The flaw is caused by improper validation of user-supplied input passed via
  the 'Expect' header from an HTTP request, which allows attackers to execute
  arbitrary HTML and script code on the web server.");

  script_tag(name:"solution", value:"Upgrade to Oracle HTTP Server 11g or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"This host is running Oracle HTTP Server and is prone to cross site
  scripting vulnerability.");

  script_xref(name:"URL", value:"http://www.oracle.com/technetwork/middleware/ias/downloads/index.html");

  exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if("Server: Oracle-Application-Server" >!< banner ||
   "Oracle-HTTP-Server" >!< banner) {
  exit(0);
}

req = string("GET /index.html HTTP/1.1\r\n",
             "Host: ",get_host_name(),"\r\n",
             "Expect: <script>alert('vt-xss-test')</script>\r\n\r\n");

res = http_keepalive_send_recv(port:port, data:req);

if(res =~ "HTTP/1\.. 200" && "Expect: <script>alert('vt-xss-test')</script>" >< res){
  security_message(port);
}
