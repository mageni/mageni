###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmailer_detect.nasl 11485 2018-09-20 06:25:34Z cfischer $
#
# PHPMailer Detection
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809841");
  script_version("$Revision: 11485 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-20 08:25:34 +0200 (Thu, 20 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-12-27 15:57:31 +0530 (Tue, 27 Dec 2016)");
  script_name("PHPMailer Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of PHPMailer Library.

  This script sends HTTP GET request and try to get the version from the
  response.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/PHPMailer-master", "/PHPMailer", "/phpmailer", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";
  mailer   = FALSE;
  conclUrl = NULL;

  foreach path( make_list( "", "/lib" ) ) {

    url = dir + path + "/composer.json";
    res = http_get_cache( item:url, port:port );

    if( res =~ "^HTTP/1\.[01] 200" && '"name": "phpmailer/phpmailer"' >< res && 'class.phpmailer.php' >< res ) {

      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      mailer = TRUE;

      foreach file( make_list( "/VERSION", "/version" ) ) {

        url = dir + path + file;
        res = http_get_cache( item:url, port:port );

        if( res =~ "^HTTP/1\.[01] 200" ) {
          vers = eregmatch( pattern:'\n([0-9.]+)', string:res );
          if( vers[1] ) {
            conclUrl += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
            version = vers[1];
            break;
          }
        }
      }
    }

    if( version ) {
      break;
    } else {
      continue;
    }
  }

  if( ! version ) {

    foreach file( make_list( "/README", "/README.md" ) ) {

      url = dir + file;
      res = http_get_cache( item:url, port:port );

      if( res =~ "^HTTP/1\.[01] 200" &&
          ( 'class.phpmailer.php' >< res && 'PHPMailer!' >< res ) ||
          ( "PHPMailer" >< res && ( "A full-featured email creation and transfer class for PHP" >< res || "Full Featured Email Transfer Class for PHP" >< res ) ) ) {

        conclUrl += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
        mailer = TRUE;

        # nb: Quite agend versions like 1.7.x or 2.2.x had ChangeLog.txt, around 5.1.x had changelog.txt
        # and newer had switched to changelog.md
        foreach file( make_list( "/changelog.txt", "/ChangeLog.txt", "/changelog.md" ) ) {

          url = dir + file;
          res = http_get_cache( item:url, port:port );

          # The typo/regex in the public release text is expected as this typo exists in the changelog.txt
          # and ChangeLog.txt but was fixed in the newer changelog.md
          if( res =~ "^HTTP/1\.[01] 200" && res =~ "Change ?Log" && res =~ "\* Ini?tial public release" ) {

            # ## Version 6.0.5 (March 27th 2018)
            # ## Version 5.2.26 (November 4th 2017)
            # Version 5.0.0 (April 02, 2009)
            # Version 5.1 (October 20, 2009)
            # Version 1.73 (Sun, Jun 10 2005)
            vers = eregmatch( pattern:'Version ([0-9.]+)', string:res );
            if( vers[1] ) {
              conclUrl += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
              version = vers[1];
              break;
            }
          }
        }
      }
      if( version ) {
        break;
      } else {
        continue;
      }
    }
  }

  if( ! version ) {

    url = dir + "/extras";
    res = http_get_cache( item:url, port:port);

    if( res =~ "^HTTP/1\.[01] 200" && res =~ "title>Index of.*extras" && '"EasyPeasyICS.php' >< res ) {

      conclUrl += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
      mailer = TRUE;
      url = dir + "/VERSION";
      res = http_get_cache( item:url, port:port );

      if( res =~ "^HTTP/1\.[01] 200" ) {
        vers = eregmatch( pattern:'\n([0-9.]+)', string:res );
        if( vers[1] ) {
          conclUrl += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE );
          version = vers[1];
        }
      }
    }
  }

  if( mailer ) {

    if( ! version )
      version = "unknown";

    set_kb_item( name:"www/" + port + "/phpmailer", value:version );
    set_kb_item( name:"phpmailer/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"([0-9.]+)", base:"cpe:/a:phpmailer_project:phpmailer:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:phpmailer_project:phpmailer";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"PHPMailer",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );