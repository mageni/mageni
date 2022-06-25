###############################################################################
# OpenVAS Vulnerability Test
# $Id: doc_browsable.nasl 14336 2019-03-19 14:53:10Z mmartin $
#
# /doc directory browsable
#
# Authors:
# Hendrik Scholz <hendrik@scholz.net>
#
# Copyright:
# Copyright (C) 2000 Hendrik Scholz
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
  script_oid("1.3.6.1.4.1.25623.1.0.10056");
  script_version("$Revision: 14336 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:53:10 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(318);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-1999-0678");
  script_name("/doc directory browsable");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2000 Hendrik Scholz");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"solution", value:"Use access restrictions for the /doc directory.
  If you use Apache you might use this in your access.conf:

  <Directory /usr/doc>
  AllowOverride None
  order deny, allow
  deny from all
  allow from localhost
  </Directory>");
  script_tag(name:"summary", value:"The /doc directory is browsable.
  /doc shows the content of the /usr/doc directory and therefore it shows which programs and - important! - the version of the installed programs.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = "/doc/";

data = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:data, bodyonly:FALSE );

buf = tolower( buf );
must_see = "index of /doc";

if( ( ereg( string:buf, pattern:"^http/[0-9]\.[0-9] 200") ) && ( must_see >< buf ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  set_kb_item( name:"www/doc_browseable", value:TRUE );
  exit( 0 );
}

exit( 99 );