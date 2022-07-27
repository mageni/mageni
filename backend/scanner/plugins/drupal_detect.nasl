###############################################################################
# OpenVAS Vulnerability Test
# $Id: drupal_detect.nasl 10891 2018-08-10 12:51:28Z cfischer $
#
# Drupal Version Detection
#
# Authors:
# Michael Meyer
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100169");
  script_version("$Revision: 10891 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 14:51:28 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_name("Drupal Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detects the installed version of Drupal.

  This script sends HTTP GET request and try to get the version from the
  response, and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit(0);

brokenDr = 0;
rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/drupal", "/drupal7", "/cms", cgi_dirs( port:port ) ) ) {

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  res  = http_get_cache( item:dir + "/update.php", port:port );
  res2 = http_get_cache( item:dir + "/", port:port );

  if( egrep( pattern:"Location: .*update\.php\?op=info", string:res, icase:TRUE ) ||
      ( egrep( pattern:"Access denied", string:res, icase:TRUE ) &&
        egrep( pattern:"drupal", string:res, icase:TRUE ) ) ||
      '<meta name="Generator" content="Drupal' >< res2 ||
      '<meta name="generator" content="Drupal' >< res2 ||
      "/misc/drupal.js?" >< res2 ||
      "jQuery.extend(Drupal.settings" >< res2 ) {

    if( dir == "" ) rootInstalled = TRUE;
    version = "unknown";

    if( egrep( pattern:"Access denied for user", string:res, icase:TRUE ) ) brokenDr++;
    if( brokenDr > 1 ) break;

    # nb: Order of the requested files matter as some provides the patch version (e.g. 8.5.1)
    # where others just provides the minor version (8.5) or even just the major version (8).

    # (Drupal < 8), this contains the patchlevel like 8.5.1 but is often blocked via .htaccess
    url = dir + "/CHANGELOG.txt";
    req = http_get( item:url, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    ver = eregmatch( pattern:'Drupal ([0-9.]+), [0-9]{4}-[0-9]{2}-[0-9]{2}', string:res, icase:TRUE );
    if( ! isnull( ver[1] ) ) {
      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
      version  = chomp( ver[1] );
    }

    if( version == "unknown" ) {
      # (Drupal >= 8), this contains the patchlevel like 8.5.1 but is often blocked via .htaccess
      url = dir + "/core/CHANGELOG.txt";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      ver = eregmatch( pattern:'Drupal ([0-9.]+), [0-9]{4}-[0-9]{2}-[0-9]{2}', string:res, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        version  = chomp( ver[1] );
      }
    }

    if( version == "unknown" ) {
      # (Drupal >= 8), this contains the patchlevel like 8.5.1 but is often blocked via .htaccess
      url = dir + "/core/modules/config/config.info.yml";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      ver = eregmatch( pattern:"version: '([0-9.]+)'", string:res, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        version  = chomp( ver[1] );
      }
    }

    if( version == "unknown" ) {
      #nb: This contains versions like 8.3, 8.4 and so on and is shipped with version 8+
      url = dir + "/composer.json";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      # "drupal/core": "~8.1"
      # "drupal/core": "^8.5"
      ver = eregmatch( pattern:'"drupal/core": ?"(\\~|\\^)([0-9.]+)"', string:res, icase:FALSE );
      if( ! isnull( ver[2] ) ) {
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
        version  = chomp( ver[2] );
      }
    }

    if( version == "unknown" ) {
      # last try to get only the major version (8, 7) from the meta generator tag
      ver = eregmatch( pattern:'<meta name="Generator" content="Drupal ([0-9.]+)', string:res2, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        conclUrl = report_vuln_url( port:port, url:dir + "/", url_only:TRUE );
        version  = chomp( ver[1] );
      }
    }

    tmp_ver = version + " under " + install;
    set_kb_item( name:"www/" + port + "/drupal", value:tmp_ver );
    set_kb_item( name:"drupal/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:drupal:drupal:" );
    if( ! cpe )
      cpe = "cpe:/a:drupal:drupal";

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Drupal",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
