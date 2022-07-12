# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100169");
  script_version("2021-12-01T11:10:56+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-12-02 11:13:31 +0000 (Thu, 02 Dec 2021)");
  script_tag(name:"creation_date", value:"2009-05-02 19:46:33 +0200 (Sat, 02 May 2009)");
  script_name("Drupal Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTT based detection of Drupal.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit(0);

brokenDr = 0;
rootInstalled = FALSE;

foreach dir( make_list_unique( "/", "/drupal", "/drupal6", "/drupal7", "/cms", http_cgi_dirs( port:port ) ) ) {

  updaterMatches = 0;

  if( rootInstalled ) break;

  install = dir;
  if( dir == "/" ) dir = "";

  res  = http_get_cache( item:dir + "/update.php", port:port );
  res2 = http_get_cache( item:dir + "/", port:port );

  # For the update.php page we might get a redirect depending on the Drupal version (6 vs. 7)
  if( res =~ "^HTTP/1\.[01] 30[12]" && egrep( pattern:"ocation: .*update\.php\?op=info", string:res, icase:FALSE ) ) {
    path = eregmatch( string:res, pattern:'Location:[ ]*http[s]?://[^/]+([^ \r\n]+)', icase:TRUE );
    if( path[1] ) {
      res = http_get_cache( item:path[1], port:port );
    }
  }

  # As the update.php page doesn't contain that much info (e.g. Drupal6 doesn't have the Generator tag) and might even be
  # translated we're using various patterns for the later check and count them to a specific number where we're sure that
  # this is the update page of Drupal.
  #
  # nb: This is used in such a way because some live Drupal pages where heavily modified and it wasn't possible to reliable
  # detect the Drupal installation on the root dir where it was indeed possible via the exposed update.php.
  if( "<title>Access denied | " >< res )
    updaterMatches++;

  if( '<meta name="Generator" content="Drupal' >< res )
    updaterMatches++;

  if( '<meta name="generator" content="Drupal' >< res )
    updaterMatches++;

  if( "$update_free_access = TRUE;" >< res )
    updaterMatches++;

  if( "$update_free_access = FALSE;" >< res )
    updaterMatches++;

  if( "/modules/system/system.css" >< res )
    updaterMatches++;

  if( "From the main Drupal directory that you installed all the files into" >< res )
    updaterMatches++;

  if( "/sites/default/files/logo.png" >< res )
    updaterMatches++;

  if( "/misc/drupal.js?" >< res )
    updaterMatches++;

  if( updaterMatches > 3 ||
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
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      version  = chomp( ver[1] );
    }

    if( version == "unknown" ) {
      # (Drupal >= 8), this contains the patchlevel like 8.5.1 but is often blocked via .htaccess
      url = dir + "/core/CHANGELOG.txt";
      req = http_get( item:url, port:port );
      res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

      ver = eregmatch( pattern:'Drupal ([0-9.]+), [0-9]{4}-[0-9]{2}-[0-9]{2}', string:res, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
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
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
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
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        version  = chomp( ver[2] );
      }
    }

    if( version == "unknown" ) {
      # last try to get only the major version (8, 7) from the meta generator tag
      ver = eregmatch( pattern:'<meta name="Generator" content="Drupal ([0-9.]+)', string:res2, icase:TRUE );
      if( ! isnull( ver[1] ) ) {
        conclUrl = http_report_vuln_url( port:port, url:dir + "/", url_only:TRUE );
        version  = chomp( ver[1] );
      }
    }

    set_kb_item( name:"drupal/detected", value:TRUE );
    set_kb_item( name:"drupal/http/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:drupal:drupal:" );
    if( ! cpe )
      cpe = "cpe:/a:drupal:drupal";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

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