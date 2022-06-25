###############################################################################
# OpenVAS Vulnerability Test
# $Id: joomla_detect.nasl 10929 2018-08-11 11:39:44Z cfischer $
#
# joomla Version Detection
#
# Authors:
# Angelo Compagnucci
#
# Copyright:
# Copyright (c) 2009 Angelo Compagnucci
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
  script_oid("1.3.6.1.4.1.25623.1.0.100330");
  script_version("$Revision: 10929 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-11 13:39:44 +0200 (Sat, 11 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)");
  script_name("joomla Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Angelo Compagnucci");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of nstalled version of joomla

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/cms", "/joomla", cgi_dirs( port:port ) ) ) {

  installed = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  buf = http_get_cache( item: dir + "/index.php", port:port );

  if( buf == NULL || "topic does not exist" >< buf || 'content="DokuWiki"' >< buf ) continue;

  if( egrep( pattern:'.*content="joomla.*', string:buf ) ||
      egrep( pattern:'.*content="Joomla.*', string:buf ) ||
      egrep( pattern:'.*href="/administrator/templates.*', string:buf ) ||
      egrep( pattern:'.*src="/media/system/js.*', string:buf ) ||
      egrep( pattern:'.*src="/templates/system.*', string:buf ) ) {

    installed = TRUE;

  } else {

    url = dir + "/.htaccess";
    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( egrep( pattern:".*# @package Joomla.*", string:buf ) ) {
      installed = TRUE;
    } else {
      url = dir + "/templates/system/css/editor.css";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( egrep( pattern:".*JOOMLA.*", string: buf ) ) {
        installed = TRUE;
      } else {
        url = dir + "/includes/js/mambojavascript.js";
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( egrep( pattern:".*@package Joomla.*", string: buf ) ) {
          installed = TRUE;
        }
      }
    }
  }

  if( installed ) {

    version = "unknown";

    url = dir + "/administrator/";

    req = http_get( item:url, port:port );
    buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
    if( buf =~ "HTTP/1.. 200" )
      language = eregmatch( string:buf, pattern:'lang="(..-..)"' );

    # Always use en-GB as a default and fallback to the detected language later
    default_lang = make_list( "en-GB" );

    if( ! isnull( language[1] ) ) {
      lang = substr( language[1], 0, 1 ) + "-" + toupper( substr( language[1], 3 ) );
      langs = make_list( default_lang, lang );
    } else {
      langs = default_lang;
    }

    foreach lang( langs ) {
      url = dir + "/administrator/language/" + lang + "/" + lang + ".xml";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf =~ "HTTP/1.. 200" )
        ver = eregmatch( string:buf, pattern:".*<version>(.*)</version>.*" );

      if( ! isnull( ver[1] ) ) {
        conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
        version = ver[1];
        break;
      }
    }

    if( version == "unknown" ) {

      url = dir + "/";
      req = http_get( item:url, port:port );
      buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

      if( buf =~ "HTTP/1.. 200" )
        language = eregmatch( string:buf, pattern:'lang="(..-..)"' );

      if( ! isnull( language[1] ) ) {
        lang = substr( language[1], 0, 1 ) + "-" + toupper( substr( language[1], 3 ) );
        langs = make_list( default_lang, lang );
      } else {
        langs = default_lang;
      }

      foreach lang ( langs ) {

        url = dir + "/language/" + lang + "/" + lang + ".xml";
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( buf =~ "HTTP/1.. 200" )
          ver = eregmatch( string:buf, pattern: ".*<version>(.*)</version>.*" );

        if( ! isnull( ver[1] ) ) {
          conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
          version = ver[1];
          break;
        }
      }

      if( version == "unknown" ) {

        url = dir + "/components/com_user/user.xml";
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( buf =~ "HTTP/1.. 200" )
          ver = eregmatch( string:buf, pattern:".*<version>(.*)</version>.*" );

        if( ! isnull( ver[1] ) ) {
          conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
          version = ver[1];
        }
      }

      if( version == "unknown" ) {

        # This file version is not really reliable
        url = dir + "/modules/mod_login/mod_login.xml";
        req = http_get( item:url, port:port );
        buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

        if( buf =~ "HTTP/1.. 200" )
          ver = eregmatch( string:buf, pattern:".*<version>(.*)</version>.*" );

        if( ! isnull( ver[1] ) ) {
          conclUrl = report_vuln_url( url:url, port:port, url_only:TRUE );
          version = ver[1];
        }
      }
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/joomla", value:tmp_version );
    set_kb_item( name:"joomla/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:joomla:joomla:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:joomla:joomla';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Joomla",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[1] ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );
