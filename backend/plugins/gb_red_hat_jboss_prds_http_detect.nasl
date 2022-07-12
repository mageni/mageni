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
  script_oid("1.3.6.1.4.1.25623.1.0.100387");
  script_version("2022-03-31T06:17:58+0000");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2009-12-10 14:34:38 +0100 (Thu, 10 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Red Hat JBoss Multiple Products Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_jboss_on_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning", "jboss_on/installed");

  script_xref(name:"URL", value:"https://www.redhat.com/en/technologies/jboss-middleware/application-platform");
  script_xref(name:"URL", value:"http://jbossas.jboss.org/");

  script_tag(name:"summary", value:"HTTP based detection of multiple Red Hat JBoss products.");

  script_tag(name:"vuldetect", value:"The following JBoss products are currently detected:

  - JBoss

  - JBoss Application Server (AS)

  - JBoss Enterprise Application Server (EAS)");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

if( get_kb_item( "jboss_on/installed" ) )
  exit( 0 );

port = http_get_port( default:8080 );

banner = http_get_remote_headers( port:port );

url1 = "/vt-test-non-existent.html";
res1 = http_get_cache( item:url1, port:port, fetch404:TRUE );
body1 = http_extract_body_from_response( data:res1 );
url2 = "/";
res2 = http_get_cache( item:url2, port:port );
body2 = http_extract_body_from_response( data:res2 );
if( ! body1 && ! body2 )
  exit( 0 );

detection_patterns = make_list(
  # <title>JBoss Web/7.5.7.Final-redhat-1 - JBWEB000064: Error report</title>
  # <h3>JBoss Web/7.5.7.Final-redhat-1</h3>
  # but also just:
  # <title>JBWEB000065: HTTP Status 404 - /vt-test-non-existent.html</title>
  # <h1>JBWEB000065: HTTP Status 404 - /vt-test-non-existent.html</h1>
  "<(title|h[0-9]+)>(JBoss Web/|JBWEB[0-9]+: )[^<]+</(title|h[0-9]+)>",
  # X-Powered-By: Servlet/3.0; JBossAS-6
  # X-Powered-By: Servlet 2.5; JBoss-5.0/JBossWeb-2.1
  # X-Powered-By: Servlet 2.4; JBoss-4.2.3.GA (build: SVNTag=JBoss_4_2_3_GA date=200807181439)/JBossWeb-2.0
  # X-Powered-By: Servlet 2.4; JBoss-4.0.5.GA (build: CVSTag=Branch_4_0 date=200610162339)/Tomcat-5.5
  # X-Powered-By: Servlet 2.4; JBoss-4.0.x/Tomcat-5.5
  # X-Powered-By: Servlet 2.4; JBoss-4.3.0.GA_CP01 (build: SVNTag=JBPAPP_4_3_0_GA_CP01 date=200804211657)/Tomcat-5.5
  # X-Powered-By: Servlet 2.4; Tomcat-5.0.28/JBoss-3.2.7 (build: CVSTag=JBoss_3_2_7 date=200501280217)
  "^[Xx]-[Pp]owered-[Bb]y\s*:.*JBoss(AS|EAS)?-",
  # <li><a href="/web-console/">JBoss Web Console</a></li>
  ">JBoss Web Console<",
  # <h1>Welcome to JBoss EAP 6</h1>
  # nb: The above is also checked via gb_red_hat_jboss_eap_http_detect.nasl but as EAP is just
  # running JBoss AS both are different products and should be detected and reported separately.
  # <title>Welcome to JBoss&trade;</title>
  # <title>Welcome to JBoss AS</title>
  # <title>Welcome to JBoss Application Server 7</title>
  "<(title|h[0-9]+)>Welcome to JBoss[^<]*</(title|h[0-9]+)>" );

found = 0;
concluded = ""; # nb: To make openvas-nasl-lint happy...

foreach pattern( detection_patterns ) {

  if( "[Xx]-[Pp]owered-[Bb]y" >< pattern ) {
    concl = egrep( string:banner, pattern:pattern, icase:FALSE );
  } else if( "JBoss Web/" >< pattern ) {
    # nb: eregmatch() is used here because the concluded string would "explode" (means too long) otherwise
    _concl = eregmatch( string:body1, pattern:pattern, icase:FALSE );
    if( _concl[1] ) {
      concl = _concl[0];
      if( ! conclUrl )
        conclUrl = "  " + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
    }
  } else {
    concl = egrep( string:body2, pattern:pattern, icase:FALSE );
  }

  if( concl ) {
    if( concluded )
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp( concl );
    concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
    concluded += "  " + concl;

    found++;
  }
}

if( found > 1 ) {

  version = "unknown";
  install = "/";

  if( conclUrl )
    conclUrl += '\n';
  conclUrl += "  " + http_report_vuln_url( port:port, url:url2, url_only:TRUE );

  # nb: Starting with version 5 only the major release is exposed in this banner.
  vers = eregmatch( pattern:"[Xx]-[Pp]owered-[Bb]y\s*:.*JBoss(AS|EAS)?-([0-9.]+[RC]*[SPGA_CP0-9]*)", string:banner, icase:FALSE );
  if( vers[2] )
    version = vers[2];

  # nb: If the version is unknown / not exposed in the banner we can also do some fingerprinting
  # based on the error page.
  # "Apache Tomcat/5.5.20", "jboss:4.0.5"
  # -> could cause FPs on normal Tomcats
  # JBoss AS 5.0.0.GA currently missing
  errorPatterns = make_array( "JBossWeb/2\.0\.0\.GA", "4.2.1", #JBoss AS 4.2.0 and 4.2.1
                              "JBossWeb/2\.0\.1\.GA", "4.2.3", #JBoss AS 4.2.2 and 4.2.3
                              "JBoss Web/2\.1\.2\.GA", "5.0.1",
                              "JBoss Web/2\.1\.3\.GA", "5.1.0",
                              "JBoss Web/3\.0\.0-CR1", "6.0.0",
                              "JBoss Web/3\.0\.0-CR2", "6.1.0",
                              "JBoss Web/7\.0\.0\.CR4", "7.0.0",
                              "JBoss Web/7\.0\.1\.Final", "7.0.2", #JBoss AS 7.0.1 and 7.0.2
                              "JBoss Web/7\.0\.10\.Final", "7.1.0",
                              "JBoss Web/7\.0\.13\.Final", "7.1.1" );

  foreach errorPattern( keys( errorPatterns ) ) {

    if( found = eregmatch( string:body1, pattern:errorPattern, icase:FALSE ) ) {

      # nb: Don't add it twice (might already exist in "concluded" in more detail.
      if( found[0] >!< concluded )
        concluded += '\n  ' + found[0];

      tmpVers = errorPatterns[errorPattern];

      if( version == "unknown" || version_is_greater( version:tmpVers, test_version:version ) )
        version = tmpVers;

      break;
    }
  }

  if( version == "unknown" ) {
    vers = eregmatch( pattern:"<title>Welcome to JBoss Application Server ([0-9.]+)[^<]*</title>", string:body2, icase:FALSE );
    if( vers[1] )
      version = vers[1];
  }

  set_kb_item( name:"redhat/jboss/as/detected", value:TRUE );
  set_kb_item( name:"redhat/jboss/as/http/detected", value:TRUE );
  set_kb_item( name:"redhat/jboss/prds/detected", value:TRUE );
  set_kb_item( name:"redhat/jboss/prds/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"(^[0-9.]+)", base:"cpe:/a:redhat:jboss_application_server:" );
  if( ! cpe ) {
    cpe = "cpe:/a:redhat:jboss_application_server";
  } else {
    if( vers =~ "(RC[0-9]+|CP[0-9]+|SP[0-9]+|GA+)" ) {
      cpe = ereg_replace( pattern:"(\.$)", string:cpe, replace:"" );
      cpeMatch = eregmatch( pattern:"(RC[0-9]+|CP[0-9]+)", string:vers );
      if( ! isnull( cpeMatch[1] ) )
        cpe += ":" + tolower( cpeMatch[1] );
    }
  }

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"Red Hat JBoss Application Server (AS)",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:conclUrl,
                                            concluded:concluded ),
               port:port );
}

exit( 0 );
