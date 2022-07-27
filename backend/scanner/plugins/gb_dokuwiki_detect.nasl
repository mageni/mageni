###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dokuwiki_detect.nasl 10873 2018-08-10 07:37:56Z cfischer $
#
# DokuWiki Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Rachana Shetty <srachana@secpod.com> on 2010-02-18
# Update to consider the bodyonly for responses
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800587");
  script_version("$Revision: 10873 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 09:37:56 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DokuWiki Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Dokuwiki.

  The script sends a connection request to the server and attempts to extract the
  version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/wiki", "/dokuwiki", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  req = http_get( item:dir + "/feed.php", port:port );
  rcv = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  req = http_get( item:dir + "/doku.php", port:port );
  rcv2 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( ( 'generator="FeedCreator' >!< rcv && 'DokuWiki"' >!< rcv )
        && "Set-Cookie: DokuWiki=" >!< rcv
        && "<error>RSS feed is disabled.</error>" >!< rcv
        && "Driven by DokuWiki" >!< rcv2
        && 'generator" content="DokuWiki' >!< rcv2 )
    continue;

  if( dir == "" ) rootInstalled = TRUE;
  version = "unknown";

  # nb: Check if the install is missing a patch. The output of this notify
  # area is currently available at http://update.dokuwiki.org/check/
  if( "://www.dokuwiki.org/update_check" >< rcv2 &&
      ( '<div class="notify">' >< rcv2 || '<div class="msg notify">' >< rcv2 ) ) {
    set_kb_item( name:"dokuwiki/missing_updates/" + port + install, value:TRUE );
    set_kb_item( name:"dokuwiki/missing_updates", value:TRUE );
  }

  # nb: The generator included the version up to release 2009-12-25
  vers = eregmatch( pattern:"DokuWiki Release (rc)?([0-9]+\-[0-9]+\-[0-9]+[a-z]?)", string:rcv2 );
  if( ! vers[2] ) {
    # nb: The VERSION file is sometimes unprotected.
    url = dir + "/VERSION";
    req = http_get( item:url, port:port );
    rcv2 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    vers = eregmatch( pattern:"(rc)?([0-9]+\-[0-9]+\-[0-9]+[a-z]?)", string:rcv2 );
    if( ! isnull( vers[2] ) ) {
      version = vers[2];
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  } else {
    version = vers[2];
  }

  tmp_version = version + " under " + install;
  set_kb_item( name:"www/" + port + "/DokuWiki", value:tmp_version );
  set_kb_item( name:"dokuwiki/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9]+\-[0-9]+\-[0-9]+[a-z]?)", base:"cpe:/a:dokuwiki:dokuwiki:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:dokuwiki:dokuwiki';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Dokuwiki",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:vers[0] ),
                                            port:port );
}

exit( 0 );
