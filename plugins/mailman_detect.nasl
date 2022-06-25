###############################################################################
# OpenVAS Vulnerability Test
# $Id: mailman_detect.nasl 11723 2018-10-02 09:59:19Z ckuersteiner $
#
# Mailman Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2005 George A. Theall
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
  script_oid("1.3.6.1.4.1.25623.1.0.16338");
  script_version("$Revision: 11723 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-02 11:59:19 +0200 (Tue, 02 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mailman Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.list.org/");

  script_tag(name:"summary", value:"This script detects whether the remote host is running Mailman and
  extracts version numbers and locations of any instances found.

  Mailman is a Python-based mailing list management package from the GNU Project.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/mailman", cgi_dirs( port:port ) ) ) {
  installed = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/listinfo";

  res = http_get_cache( item:url, port:port );
  if( isnull( res ) ) continue;

  # Find the version number. It will be in a line such as
  #   <td><img src="/icons/mailman.jpg" alt="Delivered by Mailman" border=0><br>version 2.1.5</td>
  pat = "alt=.Delivered by Mailman..+>version ([^<]+)";
  matches = egrep( pattern:pat, string:res );
  foreach match( split( matches ) ) {
    match = chomp( match );
    ver = eregmatch( pattern:pat, string:match );
    if( isnull( ver ) ) break;
    version   = ver[1];
    installed = TRUE;
    conclUrl  = report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }

  if( installed ) {
    set_kb_item( name:"gnu_mailman/detected", value:TRUE );

    cpe = "cpe:/a:gnu:mailman:" + version;
    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Mailman", version:version, install:install, cpe:cpe,
                                              concludedUrl:conclUrl, concluded:ver[0] ),
                 port:port );
  }
}

exit( 0 );
