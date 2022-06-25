###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_detect_900182.nasl 12413 2018-11-19 11:11:31Z cfischer $
#
# WordPress Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2008 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900182");
  script_version("$Revision: 12413 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-19 12:11:31 +0100 (Mon, 19 Nov 2018) $");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");
  script_name("WordPress Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of
  WordPress/WordPress-Mu.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

rootInstalled  = FALSE;
checkduplicate = ""; # nb: To make openvas-nasl-lint happy...

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit(0);

foreach dir( make_list_unique( "/", "/blog", "/wordpress", "/wordpress-mu", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  wpFound   = FALSE;
  wpMuFound = FALSE;
  version   = NULL;
  install   = dir;
  if( dir == "/" ) dir = "";

  foreach file( make_list( "/", "/index.php" ) ) {

    url = dir + file;
    res = http_get_cache( item:url, port:port );

    if( res && res =~ "^HTTP/1\.[01] 200" &&
          ( '<meta name="generator" content="WordPress' >< res ||
            res =~ "/wp-content/(plugins|themes|uploads)/" ||
            res =~ "/wp-includes/(wlwmanifest|js/)"
          )
      ) {

      if( dir == "" ) rootInstalled = TRUE;
      version  = "unknown";
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

      vers = eregmatch( pattern:"WordPress ([0-9]\.[0-9.]+)", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate ) {
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate += version + ", ";
      }

      if( "WordPress Mu" >< res ) {
        wpMuFound = TRUE;
      }

      if( "WordPress Mu" >!< res ) {
        wpFound = TRUE;
      }
    }
  }

  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/wp-links-opml.php";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res && res =~ "^HTTP/1\.[01] 200" && '<!-- generator="WordPress' >< res ) {

      if( dir == "" ) rootInstalled = TRUE;
      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

      vers = eregmatch( pattern:'<!-- generator="WordPress/([0-9.]+)', string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate ) {
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate += version + ", ";
      }
    }
  }

  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/feed/";
    res = http_get_cache( item:url, port:port );
    if( res && res =~ "^HTTP/1\.[01] 200" && "<generator>http://wordpress.org/" >< res ) {

      if( dir == "" ) rootInstalled = TRUE;
      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

      vers = eregmatch( pattern:"v=([0-9.]+)</generator>", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate ) {
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate += version + ", ";
      }
    }
  }

  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/wp-login.php";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

    if( res && res =~ "^HTTP/1\.[01] 200" &&
          ( "/wp-login.php?action=lostpassword" >< res ||
            "/wp-admin/load-" >< res ||
            res =~ "/wp-content/(plugins|themes|uploads)/"
          )
      ) {

      if( dir == "" ) rootInstalled = TRUE;
      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

      vers = eregmatch( pattern:"ver=([0-9.]+)", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate ) {
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate += version + ", ";
      }
    }
  }

  ##Finally the /readme.html file, this is down below as it might
  ##be not always updated by the admin. Additionally the version isn't
  ##exposed anymore since 3.7.x
  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/readme.html";
    res = http_get_cache( item:url, port:port );

    # <title>WordPress &rsaquo; ReadMe</title> -> 1.5.x
    # <title>WordPress &#8250; ReadMe</title> -> 4.9.x
    if( res && res =~ "^HTTP/1\.[01] 200" && res =~ "<title>WordPress.*ReadMe</title>" ) {

      if( dir == "" ) rootInstalled = TRUE;
      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

      # <h1 style="text-align: center"><img alt="WordPress" src="http://wordpress.org/images/wordpress.gif" /> <br />
      #         Version 1.5</h1>
      #
      # <h1 id="logo" style="text-align: center">
      #         <img alt="WordPress" src="wp-admin/images/wordpress-logo.png" />
      #         <br /> Version 2.5
      # </h1>
      #
      # <h1 id="logo">
      #         <a href="http://wordpress.org/"><img alt="WordPress" src="wp-admin/images/wordpress-logo.png" /></a>
      #         <br /> Version 3.6.1
      # </h1>
      vers = eregmatch( pattern:"<br />.*Version ([0-9.]+).*</h1>", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate ) {
          continue;
        }
        ##Assign detected version value to checkduplicate so as to check in next loop iteration
        checkduplicate += version + ", ";
      }
    }
  }

  if( wpMuFound ) {
    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/WordPress-Mu", value:tmp_version );
    set_kb_item( name:"wordpress/installed", value:TRUE );
    register_and_report_cpe( app:"WordPress-Mu", ver:version, conclUrl:conclUrl, concluded:vers[0], base:"cpe:/a:wordpress:wordpress_mu:", expr:"^([0-9.]+)", insloc:install, regPort:port );
  } else if( wpFound ) {
    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/WordPress", value:tmp_version );
    set_kb_item( name:"wordpress/installed", value:TRUE );
    register_and_report_cpe( app:"WordPress", ver:version, conclUrl:conclUrl, concluded:vers[0], base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port );
  }
}

exit( 0 );
