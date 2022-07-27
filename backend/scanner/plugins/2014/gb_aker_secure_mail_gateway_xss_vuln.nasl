##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_aker_secure_mail_gateway_xss_vuln.nasl 11878 2018-10-12 12:40:08Z cfischer $
#
# Aker Secure Mail Gateway Cross-Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.804413");
  script_version("$Revision: 11878 $");
  script_cve_id("CVE-2013-6037");
  script_bugtraq_id(66024);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 14:40:08 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-03-17 13:12:47 +0530 (Mon, 17 Mar 2014)");
  script_name("Aker Secure Mail Gateway Cross-Site Scripting Vulnerability");


  script_tag(name:"summary", value:"This host is running Aker Secure Mail Gateway and is prone to cross-site
scripting vulnerability.");
  script_tag(name:"vuldetect", value:"Send a crafted data via HTTP GET request and check whether it is able to read
cookie or not.");
  script_tag(name:"insight", value:"Input passed via the 'msg_id' GET parameter to webgui/cf/index.php is not
properly sanitised before being returned to the user.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary HTML and
script code in a user's browser session in context of an affected site.");
  script_tag(name:"affected", value:"Aker Secure Mail Gateway version 2.5.2 and prior");
  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/57236");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/687278");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/125599");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2014/Mar/51");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_xref(name:"URL", value:"http://www.aker.com.br/produtos/aker-secure-mail-gateway");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## default port
akerPort = get_http_port(default:80);

if(!can_host_php(port:akerPort)){
  exit(0);
}

akerReq = http_get(item:"/login", port:akerPort);
akerRes = http_keepalive_send_recv(port:akerPort, data:akerReq);

if(">Aker Secure Mail Gateway<" >< akerRes &&
   "Aker Security Solutions<" >< akerRes)
{
  url = "/webgui/cf/index.php?msg_id=><" +
       "script>alert(document.cookie);</script>";

  if(http_vuln_check(port:akerPort, url:url, check_header:TRUE,
     pattern:"><script>alert\(document.cookie\);</script>",
     extra_check:">Aker Secure Mail Gatewa"))
  {
    report = report_vuln_url( port:akerPort, url:url );
    security_message(port:akerPort, data:report);
    exit(0);
  }
}
