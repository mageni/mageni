# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900182");
  script_version("2023-03-01T10:09:26+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:09:26 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2008-12-26 14:23:17 +0100 (Fri, 26 Dec 2008)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WordPress Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of WordPress.");

  script_xref(name:"URL", value:"https://wordpress.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

# @brief Checks if the link points to the target host
function check_location( data ) {

  local_var data;
  local_var ref_list, ref, path, host_list, host;

  ref_list = egrep( pattern:"/wp\-(content|includes)/(plugins|themes|uploads)/", string:data );
  if( ! ref_list )
    return FALSE;

  ref_list = split( ref_list );

  foreach ref( ref_list ) {
    path = eregmatch( pattern:'["\']((http|/|\\.)[^"\']*wp\\-(content|includes)/[^"\']+)', string:ref );
    if( path[1] !~ "^[/.]" ) {
      host_list = make_list( get_host_ip(), get_host_names() );
      foreach host( host_list ) {
        if( ereg( pattern:"^https?://" + host, string:path[1] ) )
          return TRUE;
      }
    } else
      return TRUE;
  }

  return FALSE;
}

rootInstalled  = FALSE;
checkduplicate = ""; # nb: To make openvas-nasl-lint happy...

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/blog", "/wordpress", "/wordpress-mu", http_cgi_dirs( port:port ) ) ) {

  if( rootInstalled )
    break;

  wpFound   = FALSE;
  wpMuFound = FALSE;
  version   = "unknown";
  concluded = "";

  install = dir;
  if( dir == "/" )
    dir = "";

  foreach file( make_list( "/", "/index.php" ) ) {

    url = dir + file;
    res = http_get_cache( item:url, port:port );
    if( ! res || res !~ "^HTTP/1\.[01] 200" )
      continue;

    if( concl = egrep( string:res, pattern:'(<meta name="generator" content="WordPress|/wp-content/(plugins|themes|uploads)/|/wp-includes/(wlwmanifest|js/))', icase:FALSE ) ) {

      # Don't report WP installations on other servers
      if( '<meta name="generator" content="WordPress' >!< res ) {
        if( ! check_location( data:res ) )
          continue;
      }

      if( dir == "" )
        rootInstalled = TRUE;

      version  = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      # WordPress 5.2.9
      # <meta name="generator" content="WordPress 4.7.5" />
      vers = eregmatch( pattern:"WordPress ([0-9]\.[0-9.]+)", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate )
          continue;

        checkduplicate += version + ", ";
        concluded = "  " + vers[0];
      } else {
        # <script type='text/javascript' src='http://example.com/wp-includes/js/wp-embed.min.js?ver=4.7.5'></script>
        # <link rel='stylesheet' id='twentyseventeen-style-css'  href='http://example.com/wp-content/themes/twentyseventeen/style.css?ver=4.7.5' type='text/css' media='all' />
        # nb: Plugins have also have a "ver=" appended to their files with a lower version, the
        # strict regex below should prevent that these wrong versions are getting a match.
        vers = eregmatch( pattern:"/wp-(includes/js/wp-embed\.min\.js|content/themes/twentyseventeen/style\.css)\?ver=([0-9]+\.[0-9.]+)", string:res );
        if( vers[2] ) {
          version = vers[2];
          if( version + ", " >< checkduplicate )
            continue;

          checkduplicate += version + ", ";
          concluded = "  " + vers[0];
        }
      }

      _concl_split = split( concl, keep:FALSE );
      foreach _concl( _concl_split ) {

        # nb: Minor formatting change for the reporting.
        _concl = chomp( _concl );
        _concl = ereg_replace( string:_concl, pattern:"^(\s+)", replace:"" );

        # nb: The strings might be quite big so truncate it
        if( strlen( _concl ) > 150 )
          _concl = substr( _concl, 0, 150 ) + " (Truncated)";

        if( concluded )
          concluded += '\n';
        concluded += "  " + _concl;
      }

      if( "WordPress Mu" >< res )
        wpMuFound = TRUE;

      if( "WordPress Mu" >!< res )
        wpFound = TRUE;

      if( version != "unknown" )
        break;
    }
  }

  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/wp-links-opml.php";
    res = http_get_cache( item:url, port:port );

    if( res && res =~ "^HTTP/1\.[01] 200" &&
        concl = egrep( string:res, pattern:'<!-- generator="WordPress', icase:FALSE ) ) {

      if( dir == "" )
        rootInstalled = TRUE;

      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      # <!-- generator="WordPress/4.7.5" -->
      vers = eregmatch( pattern:'<!-- generator="WordPress/([0-9.]+)', string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate )
          continue;

        checkduplicate += version + ", ";
      }

      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/feed/";
    res = http_get_cache( item:url, port:port );

    if( res && res =~ "^HTTP/1\.[01] 200" &&
        concl = egrep( string:res, pattern:"<generator>https?://(www\.)?wordpress\.org/", icase:FALSE ) ) {

      if( dir == "" )
        rootInstalled = TRUE;

      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      vers = eregmatch( pattern:"v=([0-9.]+)</generator>", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate )
          continue;

        checkduplicate += version + ", ";
      }

      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/wp-login.php";
    res = http_get_cache( item:url, port:port );

    if( res && res =~ "^HTTP/1\.[01] 200" &&
        concl = egrep( string:res, pattern:'(/wp-login\\.php\\?action=lostpassword|/wp-admin/load-|/wp-content/(plugins|themes|uploads)/|title="Powered by WordPress")', icase:FALSE ) ) {

      # Don't report WP installations on other servers
      if( "'/wp-login.php?action=lostpassword" >!< res && "/wp-admin/load-" >!< res ) {
        if( ! check_location( data:res ) )
          continue;
      }

      if( dir == "" )
        rootInstalled = TRUE;

      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

      # <link rel='stylesheet' href='http://example.com/wp-admin/load-styles.php?c=0&amp;dir=ltr&amp;load%5B%5D=dashicons,buttons,forms,l10n,login&amp;ver=4.7.5' type='text/css' media='all' />
      vers = eregmatch( pattern:"ver=([0-9]+\.[0-9.]+)", string:res );
      if( vers[1] ) {
        version = vers[1];
        if( version + ", " >< checkduplicate )
          continue;

        checkduplicate += version + ", ";

        if( concluded )
          concluded += '\n';
        concluded = "  " + vers[0];
      }

      _concl_split = split( concl, keep:FALSE );
      foreach _concl( _concl_split ) {

        # nb: Minor formatting change for the reporting.
        _concl = chomp( _concl );
        _concl = ereg_replace( string:_concl, pattern:"^(\s+)", replace:"" );
        if( concluded )
          concluded += '\n';
        concluded += "  " + _concl;
      }
    }
  }

  # Finally the /readme.html file, this is down below as it might be not always updated by the admin.
  # Additionally the version isn't exposed anymore since 3.7.x.
  if( ( ! wpMuFound && ! wpFound ) || version == "unknown" ) {

    url = dir + "/readme.html";
    res = http_get_cache( item:url, port:port );

    # <title>WordPress &rsaquo; ReadMe</title> -> 1.5.x
    # <title>WordPress &#8250; ReadMe</title> -> 4.9.x
    if( res && res =~ "^HTTP/1\.[01] 200" &&
        concl = egrep( string:res, pattern:"<title>WordPress[^<]+ReadMe</title>", icase:FALSE ) ) {

      if( dir == "" )
        rootInstalled = TRUE;

      wpFound  = TRUE;
      version  = "unknown";
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

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
        if( version + ", " >< checkduplicate )
          continue;

        checkduplicate += version + ", ";
        if( concluded )
          concluded += '\n';
        concluded = "  " + str_replace( string:vers[0], find:'\n', replace:"<newline>" );
      }

      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  if( wpMuFound ) {
    set_kb_item( name:"wordpress/detected", value:TRUE );
    set_kb_item( name:"wordpress/http/detected", value:TRUE );
    register_and_report_cpe( app:"WordPress-Mu", ver:version, conclUrl:conclUrl, concluded:concluded, base:"cpe:/a:wordpress:wordpress_mu:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www" );
  } else if( wpFound ) {
    set_kb_item( name:"wordpress/detected", value:TRUE );
    set_kb_item( name:"wordpress/http/detected", value:TRUE );
    register_and_report_cpe( app:"WordPress", ver:version, conclUrl:conclUrl, concluded:concluded, base:"cpe:/a:wordpress:wordpress:", expr:"^([0-9.]+)", insloc:install, regPort:port, regService:"www" );
  }
}

exit( 0 );
