# SPDX-FileCopyrightText: 2008 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900129");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"creation_date", value:"2008-10-03 15:12:54 +0200 (Fri, 03 Oct 2008)");
  script_name("phpMyAdmin Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2008 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of phpMyAdmin.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) ) exit( 0 );

# nb: check if there is some kind of "alias" accepting any spelling of "phpmyadmin". If yes, stop after first detection.
check_dirs = make_list( "/pHpmyADmiN", "/PhPmyAdMin", "/phPmYaDmiN", "/phpMyadMiN" );

alias = TRUE;
ac = 0;

foreach cd( check_dirs ) {
  res = http_get_cache( item:cd + "/index.php", port:port );
  if( res !~ "^HTTP/1\.[01] 200" ) {
    alias = FALSE;
    ac = 0;
    break;
  }
  ac++;
}

if( ac != 4 )
  alias = FALSE;

foreach dir( make_list_unique( "/", "/phpmyadmin", "/phpMyAdmin", "/phpMyAdminOLD", "/pma", "/PHPMyAdmin", "/3rdparty/phpMyAdmin", "/3rdparty/phpmyadmin", "/.tools/phpMyAdmin/current", http_cgi_dirs( port:port ) ) ) {

  # nb: Avoid doubled detection via the Set-Cookie: and similar pattern of the setup page below.
  if( "/setup" >< dir )
    continue;

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache( item:url, port:port );

  if( egrep( pattern:"^Set-Cookie: pma_.*", string:res ) ||
      egrep( pattern:"^Set-Cookie: phpMyAdmin.*", string:res ) ||
      egrep( pattern:"phpMyAdmin was unable to read your configuration file", string:res ) ||
      egrep( pattern:"<title>phpMyAdmin.*", string:res ) ||
      egrep( pattern:"href=.*phpmyadmin\.css\.php", string:res ) ||
      ( egrep( pattern:"pma_password", string:res ) && egrep( pattern:"pma_username", string:res ) ) ) {

    version = "unknown";

    vers = eregmatch( pattern:"phpMyAdmin (([0-9.]+)(-[betadevrc0-9]*)?)", string:res );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
      conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    #if host is installed with newer version of phpmyadmin (>4.2.x)
    if( version == "unknown" ) {
      url = dir + "/README";
      res1 = http_get_cache( item:url, port:port );
      vers = eregmatch( pattern:"Version (([0-9.]+)(-[betadevrc0-9]*)?)", string:res1 );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      url = dir + "/doc/html/index.html";
      res1 = http_get_cache( item:url, port:port );
      vers = eregmatch( pattern:"phpMyAdmin (([0-9.]+)(-[betadevrc0-9]*)?) documentation", string:res1 );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    #extra check for bug in debian package 4.2 which shipped a wrong symlink
    if( version == "unknown" ) {
      url = dir + "/docs/html/index.html";
      res1 = http_get_cache( item:url, port:port );
      vers = eregmatch( pattern:"phpMyAdmin (([0-9.]+)(-[betadevrc0-9]*)?) documentation", string:res1 );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      url = dir + "/ChangeLog";
      req = http_get( item:url, port:port ); # nb: Don't use http_get_cache here (see the bodyonly:TRUE below)...
      res1 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      if( "phpMyAdmin - ChangeLog" >< res1 ) {
        vers = eregmatch( pattern:"(([0-9.]+)(-[betadevrc0-9]*)?) \(", string:res1 );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    if( version == "unknown" ) {
      url = dir + "/Documentation.html";
      res1 = http_get_cache( item:url, port:port );
      vers = eregmatch( pattern:"phpMyAdmin (([0-9.]+)( -[betadevrc0-9]*)?) Documentation", string:res1 );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    if( version == "unknown" ) {
      url = dir + "/changelog.php";
      req = http_get( item:url, port:port ); # nb: Don't use http_get_cache here (see the bodyonly:TRUE below)...
      res1 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      if( "phpMyAdmin - ChangeLog" >< res1 ) {
        vers = eregmatch( pattern:"(([0-9.]+)(-[betadevrc0-9]*)?) \(", string:res1 );
        if( ! isnull( vers[1] ) ) {
          version = vers[1];
          conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
        }
      }
    }

    protected = 0;

    if( egrep( pattern:"1045", string:res ) ||
        egrep( pattern:"phpMyAdmin was unable to read your configuration file", string:res ) ) {
      protected = 2; # broken config
    }

    if( egrep( pattern:"pma_username", string:res ) &&
        egrep( pattern:"pma_password", string:res ) ) {
      protected = 1; # username password required
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/phpMyAdmin", value:tmp_version );
    set_kb_item( name:"phpMyAdmin/installed", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+.*(-[betadevrc0-9]*)?)", base:"cpe:/a:phpmyadmin:phpmyadmin:" );
    if( ! cpe )
      cpe = "cpe:/a:phpmyadmin:phpmyadmin";

    if( protected == 0 ) {
      info = '- Not protected by Username/Password';
    } else if( protected == 2 ) {
      info = '- Problem with configuration file';
    } else {
      info = '- Protected by Username/Password';
    }

    # nb: Sometimes the if /setup/ dir is unprotected
    url = dir + "/setup/";
    res1 = http_get_cache( item:url, port:port );
    if( "<title>phpMyAdmin setup</title>" >< res1 )
      info = '\n- Possible unprotected setup dir identified at ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"phpMyAdmin",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:vers[0],
                                              concludedUrl:conclUrl,
                                              extra:info ),
                 port:port );
    if( alias )
      break;
  }
}

exit( 0 );
