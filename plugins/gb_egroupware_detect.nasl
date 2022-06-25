###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_egroupware_detect.nasl 7392 2017-10-10 09:59:08Z asteins $
#
# EGroupware Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100823");
  script_version("$Revision: 7392 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-10 11:59:08 +0200 (Tue, 10 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-09-24 14:46:08 +0200 (Fri, 24 Sep 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("EGroupware Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of EGroupware.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/egw", "/egroupware", "/groupware", "/eGroupware/egroupware", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/login.php";
  buf = http_get_cache( item:url, port:port );
  if( isnull( buf ) ) continue;

  if( buf =~ "HTTP/1.. 200" && (
      "<title>eGroupWare [Login]</title>" >< buf ||
      "<title>EGroupware [Login]</title>" >< buf ||
      '<meta name="author" content="EGroupware' >< buf ||
      '<meta name="keywords" content="EGroupware' >< buf ||
      '<meta name="description" content="EGroupware' >< buf ||
      '<meta name="copyright" content="EGroupware' >< buf ||
      ( '<div id="divLogo"><a href=' >< buf && "<!-- BEGIN registration -->" >< buf && "<!-- END registration -->" >< buf )
                               )
    ) {

    vers = "unknown";

    url = dir + "/setup/index.php";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    version = eregmatch( string:buf, pattern:"version ([0-9.]+)", icase:TRUE );
    if( ! isnull( version[1] ) ) {
      concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      vers = chomp( version[1] );
    } else {
      url = dir + "/status.php";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      version = eregmatch( string:buf, pattern:'versionstring":"EGroupware ([0-9.]+)"', icase:TRUE );
      if( ! isnull( version[1] ) ) {
        concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        vers = version[1];
      }
    }

    # EGroupware's version has been unified since 16.1 (no more differences between various editions)
    # The patterns above don't match to the exact versions that are being declared vulnerable in a vulnerability report
    if( vers == "unknown" || vers =~ "^16" )  {
      url = dir + "/doc/rpm-build/debian.changes";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      version = eregmatch( pattern:"egroupware-epl \(([0-9.]+)\)", string:buf);
      if( ! isnull( version[1] ) ) {
        concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        vers = version[1];
      }
    }

    tmp_version = vers + " under " + install;
    set_kb_item( name:"www/" + port + "/egroupware", value:tmp_version );
    set_kb_item( name:"egroupware/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:egroupware:egroupware:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:egroupware:egroupware';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"EGroupware",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0],
                                              concludedUrl:concludedUrl ),
                                              port:port );
  }
}

exit( 0 );
