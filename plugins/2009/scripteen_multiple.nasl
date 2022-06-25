###############################################################################
# OpenVAS Vulnerability Test
# $Id: scripteen_multiple.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# Scripteen Free Image Hosting Script Multiple Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100246");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2009-07-26 19:54:54 +0200 (Sun, 26 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2892");
  script_bugtraq_id(35800, 35801);
  script_name("Scripteen Free Image Hosting Script Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Scripteen Free Image Hosting Script is prone to multiple SQL-injection
  vulnerabilities and to an authentication-bypass vulnerability.");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to compromise the
  application, access or modify data, exploit latent vulnerabilities
  in the underlying database or to gain administrative access.");

  script_tag(name:"affected", value:"Scripteen Free Image Hosting Script 2.3 is vulnerable. Other versions
  may also be affected.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35800");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35801");
  script_xref(name:"URL", value:"http://www.scripteen.com/scripts/scripteen-free-image-hosting-script.html#more-10");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/login.php");
  buf = http_get_cache(item:url, port:port);

  if(egrep(pattern: "Scripteen Free Image Hosting Script", string: buf, icase: TRUE)) {

    url = dir + "/admin/";
    req = string("GET ", url, " HTTP/1.1\r\n",
              "Host: ", host, "\r\n",
              "User-Agent: ", http_get_user_agent(), "\r\n",
              "Accept-Language: en-us,en,de;\r\n",
              "Cookie: cookgid=1\r\n",
              "Connection: close\r\n\r\n");
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    if(egrep(pattern:"Admin Control Panel", string:buf) &&
       egrep(pattern:"Total Members", string:buf) &&
       egrep(pattern:"Total images", string:buf)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );