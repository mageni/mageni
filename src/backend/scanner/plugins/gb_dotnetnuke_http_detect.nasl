# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800683");
  script_version("2023-04-27T12:17:38+0000");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2009-09-03 16:18:01 +0200 (Thu, 03 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DNN / DotNetNuke Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.dnnsoftware.com/");

  script_tag(name:"summary", value:"HTTP based detection of DNN (formerly DotNetNuke).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

# nb:
# - DotNetNuke is nowaday just called "DNN"
# - Product can be detected, but version detection would require authentication

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:80 );
if( ! http_can_host_asp( port:port ) )
  exit( 0 );

foreach dir( make_list_unique( "/", "/dotnetduke", "/dnnarticle", "/cms", "/DotNetNuke", "/DotNetNuke Website", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  found = FALSE;
  conclUrl = NULL;

  url = dir + "/default.aspx";
  res = http_get_cache( item:url, port:port );
  url2 = dir + "/Install/InstallWizard.aspx";
  res2 = http_get_cache( item:url2, port:port );
  url3 = dir + "/DesktopModules/AuthenticationServices/OpenID/license.txt";
  res3 = http_get_cache( item:url3, port:port );
  url4 = dir + "/";
  res4 = http_get_cache( item:url4, port:port );

  if( res2 =~ "^HTTP/1\.[01] 200" && "DotNetNuke Installation Wizard" >< res2 ) {
    found = TRUE;
    conclUrl = "  " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  if( res3 =~ "^HTTP/1\.[01] 200" && "DotNetNuke" >< res3 && "www.dotnetnuke.com" >< res3 ) {
    found = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url3, url_only:TRUE );
  }

  if( res4 =~ "^HTTP/1\.[01] 200" &&
      ( ( "DotNetNuke" >< res4 || "DnnModule" >< res4 ) &&
        ( "DesktopModules" >< res4 || "dnnVariable" >< res4 || "www.dotnetnuke.com" >< res4 ||
          "DNN_HTML" >< res4 || "DotNetNukeAnonymous" >< res4 )
      ) ||
      ( res4 =~ 'id="dnn_' && res4 =~ 'class="DnnModule' )
    ) {
    found = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url4, url_only:TRUE );
  }

  if( res =~ "^HTTP/1\.[01] 200" &&
      ( ( "DotNetNuke" >< res || "DnnModule" >< res ) &&
        ( "DesktopModules" >< res || "dnnVariable" >< res || "www.dotnetnuke.com" >< res ||
          "DNN_HTML" >< res || "DotNetNukeAnonymous" >< res )
      ) ||
      ( res =~ 'id="dnn_' && res =~ 'class="DnnModule' )
    ) {
    found = TRUE;
    if( conclUrl )
      conclUrl += '\n';
    conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  if( found ) {
    version = "unknown";

    # >Welcome to DNN 6.0<
    vers = eregmatch( pattern:"(Welcome to )?DNN ([0-9.]{3,})", string:res, icase:FALSE );
    if( vers[2] )
      version = vers[2];

    if( version == "unknown" ) {
      vers = eregmatch( pattern:"(Welcome to )?DNN ([0-9.]{3,})", string:res4, icase:FALSE );
      if( vers[2] )
        version = vers[2];
    }

    set_kb_item( name:"dotnetnuke/detected", value:TRUE );
    set_kb_item( name:"dotnetnuke/http/detected", value:TRUE );

    # nb: Runs only on Windows platforms according to:
    # https://dnnsupport.dnnsoftware.com/hc/en-us/articles/360004744273-System-Requirements-for-DNN-Platform-and-DNN-Evoq
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port, desc:"DNN / DotNetNuke Detection (HTTP)", runs_key:"windows" );

    cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:dnnsoftware:dotnetnuke:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:dotnetnuke:dotnetnuke:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:dnnsoftware:dotnetnuke";
      cpe2 = "cpe:/a:dotnetnuke:dotnetnuke";
    }

    register_product( cpe:cpe1, location:install, port:port, service:"www" );
    register_product( cpe:cpe2, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"DNN / DotNetNuke",
                                              version:version,
                                              install:install,
                                              cpe:cpe1,
                                              concludedUrl:conclUrl,
                                              concluded:vers[0] ),
                 port:port );
  }
}

exit( 0 );
