# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.806501");
  script_version("2022-11-22T10:12:16+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-11-22 10:12:16 +0000 (Tue, 22 Nov 2022)");
  script_tag(name:"creation_date", value:"2015-10-19 13:01:26 +0530 (Mon, 19 Oct 2015)");
  script_name("Jasig / Apereo Central Authentication Service (CAS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_add_preference(name:"Actuator Endpoint Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Actuator Endpoint Password", value:"", type:"password", id:2);

  script_tag(name:"summary", value:"HTTP based detection of the Apereo (formerly Jasig) Central
  Authentication Service (CAS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

# nb:
# - The 'login' and/or 'id="cas' string are not always there
# - Login pages are often quite heavily customized so this currently might not catch all variants
# - A few systems also had the "Powered by" string commented out or even removed
# - Another one also didn't had the 'id="cas' but the HTML page title and cas.js was usable for the detection
# - There was another one which had the "Powered by Apereo CAS" and only the .js file without the other pattern
detection_patterns = make_list(
  # Server: Apereo CAS
  "^[Ss]erver\s*:\s*Apereo CAS",
  # <button id="cas-notifications-menu"
  # id="cas-notification-dialog" role="alertdialog"
  ' id="cas[^"]*"',
  # <form method="post" id="fm1" action="login">
  'id="fm1" action="login">',
  # >Powered by <a href="https://github.com/apereo/cas">Apereo CAS</a>
  "Powered by[^>]+>(Jasig Central Authentication Service|Apereo CAS<)",
  # <title>CAS - Central Authentication Service Login</title>
  # <title>CAS - Central Authentication Service</title>
  # <title>Login - CAS &#8211; Central Authentication Service</title>
  # nb: Title is not always there and also customizable
  "^\s*<title>[^<]*CAS (-|&#8211;) Central Authentication Service[^<]*</title>",
  # src="/js/cas.js"></script>
  # src="/cas/themes/mytheme/js/cas.js"></script>
  # src="/js/cas.js?v=0"></script>
  'src="[^>]*/js/cas\\.js[^>]*"></script>' );

foreach dir( make_list_unique( "/", "/cas", "/cas-server-webapp", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/login";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "HTTP/1\.[01] 200" )
    continue;

  banner = http_get_remote_headers( port:port, file:url );

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    if( "[Ss]erver\s*:\s*Apereo CAS" >< pattern )
      concl = egrep( string:banner, pattern:pattern, icase:FALSE );
    else
      concl = egrep( string:res, pattern:pattern, icase:FALSE );

    if( concl ) {
      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;

      # Existence of the banner is always counting as a successful detection.
      if( "[Ss]erver\s*:\s*Apereo CAS" >< pattern )
        found += 2;
      else
        found++;
    }
  }

  if( found > 1 ) {
    conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }
}

# nb: Some systems had only thrown a 404 on the root dir with this server banner but didn't had the
# "/cas/login" page exposed. As we want to use the 200 status code check above do determine first if
# the application is e.g. installed on "/cas" or "/" (for "active" checks) we need to check the
# server banner once more here to catch such systems.
if( ! found ) {
  banner = http_get_remote_headers( port:port );
  if( banner && concl = egrep( string:banner, pattern:"^[Ss]erver\s*:\s*Apereo CAS", icase:FALSE ) ) {
    install = "/";
    found += 2;
    concl = chomp( concl );
    concluded += "  " + concl;
    conclurl = http_report_vuln_url( port:port, url:install, url_only:TRUE );
  }
}

if( found > 1 ) {

  version = "unknown";

  vers = eregmatch( pattern:">Jasig Central Authentication Service ([0-9.]+)", string:res );
  if( vers[1] ) {
    version = vers[1];
    concluded += '\n  ' + vers[0];
  }

  # <code class="version">6.3.1 1/30/21, 1:41 AM</code>
  # <code class="version">6.3.7.4</code>
  # <code class="version">6.4.1 10/2/21, 12:56 PM</code>
  # <code class="version">6.4.4 3/2/22, 1:02 PM</code>
  if( version == "unknown" ) {
    vers = eregmatch( pattern:'"version">([0-9.]+)', string:res );
    if( vers[1] ) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }
  }

  # nb: Some systems have the version info removed from the HTML source code but still might provide
  # the related monitoring endpoint described in:
  # https://apereo.github.io/cas/6.5.x/monitoring/Monitoring-Statistics.html#actuator-endpoints
  # either directly without authentication (200 status code) or basic auth (401).
  if( version == "unknown" ) {

    url = dir + "/actuator/info";
    res = http_get_cache( item:url, port:port );
    if( res && res =~ "^HTTP/1\.[01] 401.+WWW-Authenticate\s*:.+" ) {

      user = script_get_preference( "Actuator Endpoint Username", id:1 );
      pass = script_get_preference( "Actuator Endpoint Password", id:2 );

      if( ! user && ! pass ) {
        extra = "Apereo CAS and '/actuator/info' endpoint detected but version unknown. Providing credentials to this VT might allow to gather the version.";
      } else if( ! user && pass ) {
        log_message( port:port, data:"Password for Actuator Endpoint provided but Username is missing." );
      } else if( user && ! pass ) {
        log_message( port:port, data:"Username for Actuator Endpoint provided but Password is missing." );
      } else if( user && pass ) {
        add_headers = make_array( "Authorization", "Basic " + base64( str:user + ":" + pass ) );
        req = http_get_req( port:port, url:url, add_headers:add_headers, accept_header:"*/*" );
        res = http_keepalive_send_recv( port:port, data:req );

        if( res !~ "^HTTP/1\.[01] 200" || '{"cas":{"' >!< res ) {
          if( ! res )
            res = "No response";
          log_message( port:port, data:'Username and Password provided but login to the Actuator Endpoint failed with the following response:\n\n' + res );
        }
      }
    }

    # {"cas":{"java":{"vendor":"Eclipse Foundation","version":"11.0.12","home":"/opt/java/openjdk"},"version":"6.4.1","date":"2021-10-02T12:56:50Z"},"git":{"branch":"6.4.x","commit":{"id":"ad3685a"}},"build":{"artifact":"cas","name":"cas","time":"2021-10-06T04:34:59.409Z","version":"6.4.1","group":"org.apereo.cas"}}
    # nb: We're using the "build" part because the other "version" one has one of at least java in
    # between and we can't parse that out in a reliable way (at least not now).
    if( res =~ "^HTTP/1\.[01] 200" && '{"cas":{"' >< res ) {
      vers = eregmatch( string:res, pattern:'"build"\\s*:\\s*\\{[^}]*"artifact"\\s*:\\s*"cas"[^}]+"version"\\s*:\\s*"([0-9.]+)[^}]+\\}' );
      if( vers[1] ) {
        version = vers[1];
        concluded += '\n  ' + vers[0];
        conclurl += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }
  }

  set_kb_item( name:"jasig_apereo/cas/detected", value:TRUE );
  set_kb_item( name:"jasig_apereo/cas/http/detected", value:TRUE );
  set_kb_item( name:"jasig_apereo/cas/http/" + port + "/installs", value:port + "#---#" + install
               + "#---#" + version + "#---#" + concluded + "#---#" + conclurl + "#---#" + extra );

  exit( 0 );
}

exit( 0 );
