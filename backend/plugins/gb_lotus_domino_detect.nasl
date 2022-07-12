###############################################################################
# OpenVAS Vulnerability Test
#
# Lotus/IBM Domino Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100597");
  script_version("2019-05-28T08:14:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-28 08:14:39 +0000 (Tue, 28 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-22 20:18:17 +0200 (Thu, 22 Apr 2010)");
  script_name("Lotus/IBM Domino Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl", "popserver_detect.nasl", "imap4_banner.nasl", "webmirror.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/pop3", 110, 995,
                       "Services/imap", 143, 993, "Services/www", 80);

  script_tag(name:"summary", value:"Detects the installed version of
  Lotus/IBM Domino.

  The script connects to SMTP (25), IMAP (143), POP3 (110) or HTTP (80) port,
  reads the banner and tries to get the Lotus/IBM Domino version from any
  of those.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

domino_ver = "unknown";
debug = 0;

ports = smtp_get_ports();
foreach port( ports ) {

  banner = get_smtp_banner( port:port );

  ehlo = get_kb_item( "smtp/fingerprints/" + port + "/ehlo_banner" );
  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

  if( ( "Lotus Domino" >< banner || "IBM Domino" >< banner ) ||
      ( "pleased to meet you" >< ehlo && "Enter one of the following commands" >< help &&
        "Reset state" >< rset && "SMTP Service closing transmission channel" >< quit && "OK" >< noop ) ) {

    install    = port + "/tcp";
    domino_ver = "unknown";
    version    = eregmatch( pattern:"(Lotus|IBM) Domino Release ([0-9][^)]+)", string:banner );

    if( ! isnull( version[2] ) )
      domino_ver = version[2];

    set_kb_item( name:"Domino/Version", value:domino_ver );
    set_kb_item( name:"Domino/Installed", value:TRUE );
    set_kb_item( name:"ibm/domino/smtp/detected", value:TRUE );
    set_kb_item( name:"SMTP/" + port + "/Domino", value:domino_ver );

    cpe = build_cpe( value:domino_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
    if( ! cpe )
      cpe = "cpe:/a:ibm:lotus_domino";

    register_product( cpe:cpe, location:install, port:port, service:"smtp" );
    log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                              version:domino_ver,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

ports = imap_get_ports();
foreach port( ports ) {

  banner = get_imap_banner( port:port );
  if( banner && "Domino IMAP4 Server" >< banner ) {

    install    = port + "/tcp";
    domino_ver = "unknown";
    version    = eregmatch( pattern:"Domino IMAP4 Server Release ([0-9][^ ]+)", string:banner );

    if( ! isnull( version[1] ) )
      domino_ver = version[1];

    set_kb_item( name:"Domino/Version", value:domino_ver );
    set_kb_item( name:"Domino/Installed", value:TRUE );

    cpe = build_cpe( value:domino_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:ibm:lotus_domino";

    register_product( cpe:cpe, location:install, port:port, service:"imap" );
    log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                              version:domino_ver,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

ports = pop3_get_ports();
foreach port( ports ) {

  banner = get_pop3_banner( port:port );

  if( banner && ( "Lotus Notes POP3 server" >< banner || "IBM Notes POP3 server" >< banner ) ) {

    install    = port + "/tcp";
    domino_ver = "unknown";
    version    = eregmatch( pattern:"(Lotus|IBM) Notes POP3 server version Release ([0-9][^ ]+)", string:banner );

    if( ! isnull( version[2] ) ) domino_ver = version[2];

    set_kb_item( name:"Domino/Version", value:domino_ver );
    set_kb_item( name:"Domino/Installed", value:TRUE );

    cpe = build_cpe( value:domino_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:ibm:lotus_domino";

    register_product( cpe:cpe, location:install, port:port, service:"pop3" );
    log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                              version:domino_ver,
                                              install:install,
                                              cpe:cpe,
                                              concluded:version[0] ),
                                              port:port );
  }
}

if( http_is_cgi_scan_disabled() ) exit( 0 );

versionFiles = make_array( "/download/filesets/l_LOTUS_SCRIPT.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_LOTUS_SCRIPT.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SEARCH.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SEARCH.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SHIMMER9.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SHIMMER8_5_en.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SHIMMER8_en.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SHIMMER8_5.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SHIMMER8.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SHIMMER9.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SHIMMER8_5_en.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SHIMMER8_en.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SHIMMER8_5.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SHIMMER8.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_MAPI.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_English.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_DOLBASE.inf", "Version=([0-9.]+)",
                           "/iNotes/Forms5.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms6.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms7.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms8.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms85.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms9.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/help/readme.nsf?OpenAbout", "Lotus Notes/Domino ([0-9.]+)", # <title>IBM Lotus Notes/Domino 8.0.2 Release Notes</title> or <title>Lotus Notes/Domino 6.0.2 Release Notes</title>
                           "/api", '\\s*"name":"Core",\\s*"enabled":[^,]*,\\s*"version":"([0-9.]+)(\\.v[0-9]+)', # { "name":"Core", "enabled":true, "version":"9.0.1.v10_00", "href":"\/api\/core" } (nb: with newlines)
                           "/homepage.nsf", ">Domino Administrator ([0-9.]+) Help</" ); # Last fallback to get the major version

cgis = "/domcfg.nsf";
final_ver = "unknown";
extra = "";

port = get_http_port( default:80 );
host = http_host_name( dont_add_port:TRUE );

nsfList = http_get_kb_file_extensions( port:port, host:host, ext:"nsf" );

tmpCgis = make_list_unique( "/", cgi_dirs( port:port ) );
foreach tmpCgi( tmpCgis ) {
  if( tmpCgi == "/" ) tmpCgi = "";
  cgis = make_list( cgis, tmpCgi + "/domcfg.nsf" );
}

if( nsfList ) {
  nsfFiles = make_list_unique( nsfList, "/nonexistent.nsf", cgis );
} else {
  nsfFiles = make_list_unique( "/nonexistent.nsf", cgis );
}

foreach nsfFile( nsfFiles ) {

  banner = get_http_banner( port:port, file:nsfFile );

  req = http_get( item:nsfFile, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( ( banner && ( "Lotus-Domino" >< banner || "Lotus Domino" >< banner ) ) ||
      ( 'src="/domcfg.nsf/' >< res && ( "self._domino_name" >< res || "Web Server Configuration" >< res ) ) ||
        'src="/webstart.nsf/IBMLogo.gif' >< res || "HTTP Web Server: IBM Notes Exception - File does not exist" >< res ) {

    concludedUrl = report_vuln_url( port:port, url:nsfFile, url_only:TRUE );
    domino_ver   = "unknown";
    installed    = TRUE;
    version = eregmatch( pattern:"Lotus-Domino/Release-([0-9.]+)", string:banner );
    inst = eregmatch( pattern:"(.*/)(.*\.nsf)", string:nsfFile );
    if( inst[1] ) {
      install = inst[1];
    } else {
      install = "/";
    }

    set_kb_item( name:"www/domino/" + port + "/dir", value:install );

    if( ! isnull( version[1] ) ) {
      domino_ver = version[1];
      concluded = version[0];
      extra += '\n' + report_vuln_url( port:port, url:nsfFile, url_only:TRUE ) + " : " + version[1];
    } else {
      extra += '\n' + report_vuln_url( port:port, url:nsfFile, url_only:TRUE ) + " : unknown";
      foreach file( keys( versionFiles ) ) {

        dir = install;
        if( dir == "/" )
          dir = "";

        url = dir + file;

        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

        if( "Version=" >< res || "Domino Release" >< res || ">Domino Administrator" >< res ||
             ( '"services":[' >< res || '"href":"\\/api\\/core"' >< res || '"name":"Core",' >< res ) ) {

          version = eregmatch( pattern:versionFiles[file], string:res );
          if( ! isnull( version[1] ) ) {

            # nb: Special handling to rewrite 9.0.1.v10 to 9.0.1FP10
            if( "/api" >< file && version[2] ) {
              version[2] = ereg_replace( string:version[2], pattern:"\.v([0-9]+)", replace:"FP\1" );
              version[1] += version[2];
            }

            extra += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE ) + " : " + version[1];

            if( domino_ver == "unknown" ) {
              domino_ver = version[1];
              concluded  = version[0];
            }

            tmp_ver = version[1];
            if( debug ) display( "Current detected version in " + url + ": " + tmp_ver + ", previous version: " + domino_ver + '\n' );
            if( version_is_greater( version:tmp_ver, test_version:domino_ver ) ) {
              domino_ver = tmp_ver;
              concluded  = version[0];
            }
          } else {
            extra += '\n' + report_vuln_url( port:port, url:url, url_only:TRUE ) + " : unknown";
          }
        }
      }
      if( concluded )
        version[0] = concluded;
    }
    if( domino_ver != "unknown" )
      final_ver = domino_ver;
  }
  if( installed && final_ver != "unknown" )
    break;
}

if( installed ) {

  install = port + "/tcp";

  set_kb_item( name:"Domino/Version", value:final_ver );
  set_kb_item( name:"dominowww/installed", value:TRUE );
  set_kb_item( name:"Domino/Installed", value:TRUE );

  cpe = build_cpe( value:final_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
  if( isnull( cpe ) ) {
    cpe = build_cpe( value:final_ver, exp:"([0-9]+)", base:"cpe:/a:ibm:lotus_domino:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:ibm:lotus_domino";
  }

  if( extra )
    extra = 'The following URLs where used for the product / version detection (URL : exposed version):\n' + extra;

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                            version:final_ver,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0],
                                            extra:extra ),
                                            port:port );
}

exit( 0 );
