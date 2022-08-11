###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_svn_entries_http.nasl 7165 2017-09-18 08:57:44Z cfischer $
#
# Apache Subversion Module Metadata Accessible
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105099");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 7165 $");
  script_name("Apache Subversion Module Metadata Accessible");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 10:57:44 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2014-10-28 14:27:24 +0100 (Tue, 28 Oct 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://techcrunch.com/2009/09/23/basic-flaw-reveals-source-code-to-3300-popular-websites/");

  script_tag(name:"vuldetect", value:"Try to read '.svn/entries'.");

  script_tag(name:"solution", value:"Restrict access to the .svn directories.");

  script_tag(name:"summary", value:"Apache Subversion Module Metadata accessible via HTTP");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

report = 'It was possible to retrieve the contents of ".svn/entries" using the following URLs : \n\n';
x = 0;
VULN = FALSE;

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  x++;

  url = dir + '/.svn/entries';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( buf == NULL ) continue;

  if( "has-props"      >< buf ||
      "has-prop-mods"  >< buf ||
      "committed-rev=" >< buf ||
      'prop-time="'    >< buf ||
      egrep( pattern:"svn:(special|needs-lock)", string:buf ) ) {
    VULN = TRUE;
    report += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
  }
  if( x > 25 ) break;
}

if( VULN ) {
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
