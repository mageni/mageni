# OpenVAS Vulnerability Test
# $Id: trac_sql_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Edgewall Software Trac SQL injection flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.20252");
  script_version("2019-04-11T14:06:24+0000");
  script_tag(name:"last_modification", value:"2019-04-11 14:06:24 +0000 (Thu, 11 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_cve_id("CVE-2005-3980");
  script_bugtraq_id(15676);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Edgewall Software Trac SQL injection flaw");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www");
  script_dependencies("find_service.nasl", "http_version.nasl");

  script_tag(name:"solution", value:"Upgrade to Trac version 0.9.1 or later.");

  script_tag(name:"summary", value:"The remote version of Trac is prone to a SQL injection flaw
  through the ticket query module due to 'group' parameter is not properly sanitized.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/418294/30/0/threaded");
  script_xref(name:"URL", value:"http://projects.edgewall.com/trac/wiki/ChangeLog");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/trac", cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  url = string(dir,"/query?group=/*");
  buf = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:TRUE);
  if(!r)
    continue;

  if("Trac detected an internal error" >< r && egrep(pattern:"<title>Oops - .* - Trac<", string:r)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );