###################################################################
# OpenVAS Vulnerability Test
# $Id: osticket_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# osTicket Detection
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.13858");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("osTicket Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects whether the target is running osTicket and extracts
  version numbers and locations of any instances found.

  osTicket is a PHP-based open source support ticket system.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.osticket.com/");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

#if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/osticket", "/osTicket", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/open.php";
  res = http_get_cache(port: port, item: url);

  # Make sure the page is from osTicket.
  if( (egrep( pattern:'alt="osTicket', string:res, icase:TRUE )) || (res =~ '(P|p)owered by osTicket')) {
    version = "unknown";
    # For older versions
    pat = "alt=.osTicket STS v(.+) *$";
    matches = egrep( pattern:pat, string:res );
    foreach match( split( matches ) ) {
      match = chomp( match );
      ver = eregmatch( pattern:pat, string:match );
      if( ver == NULL ) break;
      ver = ver[1];

      # 1.2.5, 1.2.7, and 1.3.x all report 1.2; try to distinguish among them.
      if( ver == "1.2" ) {
        # 1.3.0 and 1.3.1.
        if( "Copyright &copy; 2003-2004 osTicket.com" >< res ) {
          # nb: 1.3.1 doesn't allow calling 'include/admin_login.php' directly.
          url = dir + "/include/admin_login.php";
          req = http_get( item:url, port:port );
          res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

          if( "<td>Please login:</td>" >< res ) {
            ver = "1.3.0";
          } else if ( "Invalid path" >< res ) {
            ver = "1.3.1";
          } else {
            ver = "unknown";
          }
        # 1.2.5 and 1.2.7
        } else {
          # nb: 1.2.5 has an attachments dir whereas 1.2.7 has attachments.php
          url = dir + "/attachments.php";
          req = http_get( item:url, port:port );
          res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

          if( "You do not have access to attachments" >< res ) {
            ver = "1.2.7";
          } else if ( "404 Not Found" >< res ) {
            ver = "1.2.5";
          }
        }
      }
    }

    tmp_version = ver + " under " + install;
    set_kb_item( name:"www/" + port + "/osticket", value:tmp_version );
    set_kb_item( name:"osticket/installed", value:TRUE );

    cpe = build_cpe( value:ver, exp:"^([0-9.]+)", base:"cpe:/a:osticket:osticket:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:osticket:osticket';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"osTicket",
                                              version:ver,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                 port:port );
    exit(0);
  }
}

exit( 0 );
