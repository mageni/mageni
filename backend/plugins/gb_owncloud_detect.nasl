###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_detect.nasl 11021 2018-08-17 07:48:11Z cfischer $
#
# ownCloud Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.103564");
  script_version("$Revision: 11021 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-17 09:48:11 +0200 (Fri, 17 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-09-12 14:18:24 +0200 (Wed, 12 Sep 2012)");
  script_name("ownCloud Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gb_nextcloud_detect.nasl"); # Nextcloud needs to be detected before
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of ownCloud.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );
host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", "/oc", "/owncloud", "/ownCloud", "/OwnCloud", "/cloud", cgi_dirs( port:port ) ) ) {

  if( get_kb_item( "nextcloud/install/" + host + "/" + port + "/" + dir ) ) continue; # From gb_nextcloud_detect.nasl to avoid double detection of Nextcloud and ownCloud

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/status.php";
  buf = http_get_cache( item:url, port:port );

  # nb: Try again with the IP which might be included in the trusted_domain setting.
  # This could could allow us to gather the version.
  if( "You are accessing the server from an untrusted domain" >< buf ) {
    req = http_get_req( port:port, url:url, host_header_use_ip:TRUE );
    buf = http_keepalive_send_recv( port:port, data:req );
  }

  # nb: Don't check for 200 as a 400 will be returned when accessing via an untrusted domain
  # Example responses:
  # {"installed":"true","maintenance":"false","needsDbUpgrade":"false","version":"10.0.2.1","versionstring":"10.0.2","edition":"Community","productname":"ownCloud"}
  # {"installed":"true","maintenance":"false","needsDbUpgrade":"false","version":"10.0.2.9","versionstring":"10.0.2 RC1","edition":"Community","productname":"ownCloud"}
  if( "egroupware" >!< tolower( buf ) && # EGroupware is using the very same status.php
      '"productname":"Nextcloud"' >!< buf && # Don't detect Nextcloud as ownCloud
    ( egrep( string:buf, pattern:'"installed":("true"|true),("maintenance":("true"|true|"false"|false),)?("needsDbUpgrade":("true"|true|"false"|false),)?"version":"([0-9.a]+)","versionstring":"([0-9. a-zA-Z]+)","edition":"(.*)"' ) ||
      ( "You are accessing the server from an untrusted domain" >< buf && ">ownCloud<" >< buf ) ||
      '"productname":"ownCloud"' >< buf ) ) { # Last fallback if the syntax of the status has changed

    version = "unknown";
    extra = NULL;
    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    #Basic auth check for default_http_auth_credentials.nasl
    foreach authurl( make_list( dir + "/remote.php/dav", dir + "/remote.php/webdav" ) ) {

      req = http_get( item:authurl, port:port );
      buf2 = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf2 =~ "^HTTP/1\.[01] 401" ) {
        set_kb_item( name:"www/content/auth_required", value:TRUE );
        set_kb_item( name:"www/" + host + "/" + port + "/content/auth_required", value:authurl );
        break;
      }
    }

    ver = eregmatch( string:buf, pattern:'version":"([0-9.a]+)","versionstring":"([0-9. a-zA-Z]+)"', icase:TRUE );
    if( ! isnull( ver[2] ) ) version = ereg_replace( pattern:" ", replace:"", string:ver[2] );

    set_kb_item( name:"owncloud_or_nextcloud/installed", value:TRUE );
    set_kb_item( name:"owncloud/installed", value:TRUE );

    if( "You are accessing the server from an untrusted domain" >< buf ) {
      extra = "ownCloud is blocking full access to this server because the scanner is accessing the server via an untrusted domain.";
      extra += " To fix this configure the scanner to access the server on the expected domain.";
    }

    cpe = build_cpe( value:version, exp:"^([0-9.a]+)", base:"cpe:/a:owncloud:owncloud:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:owncloud:owncloud';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"ownCloud",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              extra:extra,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
