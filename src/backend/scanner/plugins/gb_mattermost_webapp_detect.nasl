###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mattermost_webapp_detect.nasl 11427 2018-09-17 09:48:09Z cfischer $
#
# Mattermost Server Webapp Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108464");
  script_version("$Revision: 11427 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 11:48:09 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-09-17 09:44:56 +0200 (Mon, 17 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Mattermost Server Webapp Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8065);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server
  and attempts to identify an installed Webapp of a Mattermost Server and its version
  from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

rootInstalled = FALSE;
port = get_http_port( default:8065 );

foreach dir( make_list_unique( "/", "/mattermost", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;
  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  buf = http_get_cache( item:url, port:port );
  if( ! buf || buf !~ "^HTTP/1\.[01] 200" ) continue;

  # nb: Pattern verified from the current 5.3.0 down to 3.2.0
  if( ( "<title>Mattermost</title>" >< buf &&
        "content=Mattermost>" >< buf ) ||
      "<noscript> To use Mattermost, please enable JavaScript. </noscript>" >< buf ||
      "<div class=error-screen> <h2>Cannot connect to Mattermost</h2>" >< buf ||
      "re having trouble connecting to Mattermost. If refreshing this page (Ctrl+R or Command+R) does not work, please verify that your computer is connected to the internet." >< buf ) {

    if( install == "/" ) rootInstalled = TRUE;
    version = "unknown";

    # nb: Sometimes a response contains the version within the Etag header like
    # Etag: 5.3.0.828a93b033f9e54901f35f13f99e677e
    # but this seems to be random and not reliable.

    # nb: Used in the current 5.3.0 as well, verify this in further updates
    # to see if the API is dropped / replaced with v5 or similar.
    # The API is available without authentication up to the current 5.3.0.
    url = dir + "/api/v4/config/client?format=old";
    req = http_get( item:url, port:port );
    # nb: Don't use the "buf" variable for the response which is used later...
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    # ","BuildNumber":"5.3.0-rc5","
    # ","BuildNumber":"5.3.0","
    # nb: This page has also ","Version":"5.3.0" but it seems the BuildNumber also contains the pre-releases
    ver = eregmatch( pattern:'","BuildNumber":"([^"]+)","', string:res );
    if( ! isnull( ver[1] ) ) {
      version = ereg_replace( pattern:"-", string:ver[1], replace:"." );
      concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( version == "unknown" ) {

      # Available in e.g. 3.2.0 and 4.5.0 but not in newer like 5.3.0
      url = dir + "/api/v3/users/initial_load";

      req = http_get( item:url, port:port );
      # nb: Don't use the "buf" variable for the response which is used later...
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      # ","BuildNumber":"3.2.0","
      # ","BuildNumber":"4.5.2","
      # nb: Same for the version above is valid here as well...
      # ","Version":"3.2.0","
      ver = eregmatch( pattern:'","BuildNumber":"([^"]+)","', string:res );
      if( ! isnull( ver[1] ) ) {
        version = ereg_replace( pattern:"-", string:ver[1], replace:"." );
        concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    # nb: Keep at the bottom as the checks above are more reliable...
    if( version == "unknown" ) {

      # X-Version-Id: 5.3.0.5.3.0-rc5.05f56833d55fb06ecc1c6b1ee590905f.false
      # X-Version-Id: 5.3.0.5.3.0.cd003a2f2eb0b30c5974fd7fec9d0497.false
      # nb: This was 4.8.2:
      # X-Version-Id: 4.8.1.4.8.2.197db85daa27df6f95d558cef762ca4e.false
      # nb: this 4.5.2:
      # X-Version-Id: 4.5.0.4.5.2.a238f5530071d28a54eedc6814dc0017.false
      # nb: and this 3.10.3:
      # X-Version-Id: 3.10.0.3.10.3.d02f602aaad5c111f62c8d32edb13dae.false
      # nb: 3.2.0 had no doubled version
      # X-Version-Id: 3.2.0.1469389756

      fullver = egrep( pattern:"^X-Version-Id: [^\r\n]+", string:buf );
      if( fullver ) {
        fullver = chomp( fullver );
        ver = eregmatch( pattern:"^X-Version-Id: (.*)", string:fullver );
        if( ver[1] ) {
          _fullver = split( ver[1], sep:".", keep:FALSE );
          if( max_index( _fullver ) == 4 ) {
            version = _fullver[0] + "." + _fullver[1] + "." + _fullver[2];
          } else if( max_index( _fullver ) == 8 ) {
            version = _fullver[3] + "." + _fullver[4] + "." + _fullver[5];
          }
          version = ereg_replace( pattern:"-", string:version, replace:"." );
        }
      }
    }

    # CPE is not registered yet
    cpe = build_cpe( value:version, exp:"^([0-9.a-z]+)", base:"cpe:/a:mattermost:mattermost:");
    if( isnull( cpe ) )
      cpe = "cpe:/a:mattermost:mattermost";

    set_kb_item( name:"www/" + port + "/mattermost_server", value:version );
    set_kb_item( name:"mattermost_server/detected", value:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Mattermost Server Webapp",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0],
                                              concludedUrl:concludedUrl ),
                                              port:port );
  }
}

exit( 0 );
