##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gdl_mult_sql_inj_n_xss_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Ganesha Digital Library Multiple SQL Injection and XSS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802433");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-06-01 13:02:10 +0530 (Fri, 01 Jun 2012)");
  script_name("Ganesha Digital Library Multiple SQL Injection and XSS Vulnerabilities");
  script_xref(name:"URL", value:"http://1337day.com/exploits/18392");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18953/");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/113132/ganesha-sqlxss.txt");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to steal cookie
  based authentication credentials, compromise the application, access or modify
  data or exploit latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"Ganesha Digital Library 4.0 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to

  - Input passed via the 'm' parameter to office.php, the 'id' parameter
  to publisher.php, and the 's' parameter to search.php is not properly
  sanitised before being returned to the user.

  - Input passed via the 'node' parameter to go.php is not properly
  sanitised before being used in SQL queries.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"This host is running Ganesha Digital Library and prone to multiple
  SQL injection and cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/GDL",  cgi_dirs(port:port)))
{
  if(dir == "/") dir = "";
  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  if( res =~ "HTTP/1.. 200" && ">KBPublisher<" >< res && "<title>Welcome - ACME Digital Library -  GDL" >< res ) {

    url = dir + "/publisher.php?id='mehaha!!!";

    if(http_vuln_check( port: port, url: url, check_header: TRUE,
       pattern: ">You have an error in your SQL syntax near 'mehaha!!!'",
       extra_check: ">PublisherID:</"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);