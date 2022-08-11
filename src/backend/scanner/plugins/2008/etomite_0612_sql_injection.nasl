###############################################################################
# OpenVAS Vulnerability Test
# $Id: etomite_0612_sql_injection.nasl 10781 2018-08-06 07:41:20Z cfischer $
#
# Etomite CMS id Parameter SQL Injection
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.80057");
  script_version("$Revision: 10781 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-06 09:41:20 +0200 (Mon, 06 Aug 2018) $");
  script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-6048");
  script_bugtraq_id(21135);
  script_name("Etomite CMS id Parameter SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2006 Justin Seitz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to
  upgrade to a newer release, disable respective features, remove the product or replace the product by
  another one.");

  script_tag(name:"summary", value:"The remote web server contains a PHP script that is affected by a SQL
  injection vulnerability.

  Description:

  The remote web server is running Etomite CMS, a PHP-based content
  management system.

  The version of Etomite CMS installed on the remote host fails to
  sanitize input to the 'id' parameter before using it in the
  'index.php' script in a database query.");

  script_tag(name:"impact", value:"Provided PHP's 'magic_quotes_gpc' setting is disabled, an unauthenticated
  attacker can exploit this issue to manipulate SQL queries, possibly leading to disclosure of sensitive data,
  attacks against the underlying database, and the like.");


  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

injectstring = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_", length:10);

foreach dir( make_list_unique( "/etomite", "/cms", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/index.php?id=", injectstring, "'");
  req = http_get(item:url,port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (isnull(res)) continue;

  sqlstring = "";
  if(string("etomite_site_content.id = '", injectstring) >< res) {
    sqlstring = res;
    if("<span id='sqlHolder'>" >< sqlstring)
      sqlstring = strstr(sqlstring,"SELECT");
    if("</span></b>" >< sqlstring)
      sqlstring = sqlstring - strstr(sqlstring, "</span></b>");

    info = string("The version of Etomite CMS installed in directory '", dir, "'\n",
                  "is vulnerable to this issue. Here is the resulting SQL string\n",
                  "from the remote host when using a test string of '",injectstring,"'  :\n\n", sqlstring);
    security_message(data:info, port:port);
    exit(0);
  }
}

exit( 99 );