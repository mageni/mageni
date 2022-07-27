###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpBugTracker_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# phpBugTracker Detection
#
# Authors:
# Michael Meyer
#
# Updated by: Antu Sanadi <santu@secpod.com> on 2011-03-22
# Updated the application confirmation check at line 82
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
  script_oid("1.3.6.1.4.1.25623.1.0.100217");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("phpBugTracker Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This host is running phpBugTracker, a web-based bug tracker with
 functionality similar to other issue tracking systems, such as Bugzilla.");

  script_xref(name:"URL", value:"http://phpbt.sourceforge.net/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/phpbt", "/bugtracker", "/bugs", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( ( egrep( pattern:"<title>phpBugTracker - Home</title>", string:buf, icase:TRUE ) ||
        egrep( pattern:"<title>Home - phpBugTracker</title>", string:buf, icase:TRUE ) ) &&
        egrep( pattern:"bug.php\?op=add", string:buf, icase:TRUE ) ) {

    version = "unknown";

    req = http_get( item:dir + "/CHANGELOG", port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    ver = eregmatch( string:buf, pattern:'-- ([0-9.]+)' );

    if ( ! isnull( ver[1] ) ) version = ver[1];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/phpBugTracker", value:tmp_version );
    set_kb_item( name:"phpBugTracker/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+?)", base:"cpe:/a:benjamin_curtis:phpbugtracker:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:benjamin_curtis:phpbugtracker';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"phpBugTracker",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
