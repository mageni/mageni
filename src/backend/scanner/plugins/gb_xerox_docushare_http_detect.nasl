# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.104315");
  script_version("2022-09-08T10:11:29+0000");
  script_tag(name:"last_modification", value:"2022-09-08 10:11:29 +0000 (Thu, 08 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-06 11:36:45 +0000 (Tue, 06 Sep 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Xerox DocuShare Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.xerox.com/en-us/services/enterprise-content-management");

  script_tag(name:"summary", value:"HTTP based detection of Xerox DocuShare.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("os_func.inc");

SCRIPT_DESC = "Xerox DocuShare Detection (HTTP)";

port = http_get_port( default:443 );

detection_patterns = make_list(
  # <title>DocuShare</title>
  # <title>DocuShare Login</title>
  # nb: Title can be also something arbitrary like "<title>Foo Bar Login</title>"
  "^\s+<title>DocuShare( Login)?</title>",
  # nb: The C in "Copyright" below was actually U+00A9
  # <p rel="copyright" id="copyright_text">Copyright C 1996-2020 Xerox Corporation.  All Rights Reserved.</p>
  # <p rel="copyright" id="copyright_text">Copyright C 1996-2011 Xerox Corporation.  All Rights Reserved.</p>
  # <a href="http://www.xerox.com" title="Go to Xerox.com"><span></span>Go to Xerox.com</a>
  # nb: Those are not split into two pattern to avoid that both strings (which might be valid for
  # other products as well) are already counted as a successful detection.
  "^\s+<[ap] .+([Xx]erox\.com|Xerox Corporation\.).+</[ap]>",
  # <li><a href="http://docushare.xerox.com/launchpad.html" target="_blank">DocuShare.xerox.com</a></li>
  "docushare\.xerox\.com.+DocuShare\.xerox\.com",
  # <li><a href="/docushare/dsweb/About">About DocuShare</a></li>
  ">About DocuShare<",
  # <link rel="stylesheet" type="text/css" href="/themes/blue/docushare_quicksearch.css" />
  # <link rel="stylesheet" type="text/css" href="/docushare/themes/earthtone/docushare_quicksearch.css" />
  '^\\s*<link rel="stylesheet".+/docushare_quicksearch\\.css" />',
  # <h1 id="welcome_message">
  #   Welcome to DocuShare!
  #
  # </h1>
  '^\\s*Welcome to DocuShare![\r\n]*$' );

# nb: While the default seems to be "/docushare/dsweb" some live systems also just used "/dsweb".
foreach dir( make_list_unique( "/", "/docushare", "/share", http_cgi_dirs( port:port ) ) ) {

  # Note that at least one active check is appending "/dsweb" to the crafted HTTP request so this
  # needs to be checked if the "install" variable is getting changed.
  install = dir;
  if( dir == "/" )
    dir = "";

  # nb: A VT from 2014 (gb_xerox_docushare_url_sql_inj_vuln.nasl) had used this detection
  # endpoint and newer versions of the product is using it as well so this should be fine for now...
  url = dir + "/dsweb/HomePage";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "^HTTP/1\.[01] 200" )
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern( detection_patterns ) {

    concl = egrep( string:res, pattern:pattern, icase:FALSE );
    if( concl ) {

      found++;

      if( concluded )
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp( concl );
      concl = ereg_replace( string:concl, pattern:"^(\s+)", replace:"" );
      concluded += "  " + concl;
    }
  }

  # nb: Two found pattern should be enough for now to proof a detection...
  if( found > 1 ) {

    set_kb_item( name:"xerox/docushare/detected", value:TRUE );
    set_kb_item( name:"xerox/docushare/http/detected", value:TRUE );
    conclUrl = "  " + http_report_vuln_url( port:port, url:url, url_only: TRUE );
    version = "unknown";

    # nb: Some systems have the version directly included in some URLs like e.g.:
    # <link rel="shortcut icon" href="/favicon.ico?v=7.5.0.C1.215" type="image/x-icon" />
    # <script src="/javascript/common/jquery/dist/jquery.min.js?v=7.5.0.C1.215" > </script>
    #
    # or:
    #
    # <link rel="shortcut icon" href="/docushare/favicon.ico?v=7.0.0.C1.609" type="image/x-icon" />
    # <link rel="stylesheet" type="text/css" href="/docushare/themes/blue/docushare_quicksearch.css?v=7.0.0.C1.609" />
    #
    # nb: The regex was made a little bit more strict to avoid that we're catching something which isn't a version
    vers = eregmatch( pattern:'\\.(ico|png|css|js)\\?v=([0-9]+\\.[0-9]+\\.[0-9]+[^"]*)" />', string:res );
    if( vers[2] ) {
      version = vers[2];
      concluded += '\n  ' + vers[0];
    }

    # nb: Sometime protected via a login (at least in 7.x versions), still trying to grab the version
    # if unknown up to now but available here. It is also always checked because the version might
    # have been already grabbed previously but we could still idenfity the OS from this page if
    # available.
    url = dir + "/dsweb/About";
    res = http_get_cache( item:url, port:port );
    if( res && res =~ "^HTTP/1\.[01] 200" ) {

      # <div class="licenseinfo">
      #
      # Version 6.6.1.C1.139 Linux (Build 6.6.1.C1.139)<br />
      #
      # Updates:[
      # ds661hf4,ds661update1,ds661postInstallFix
      #
      # ]<br />
      #
      # or:
      #
      # <div class="licenseinfo">
      #
      # Version 7.5.0.C1.215 Linux (Build 7.5.0.C1.215)<br />
      #
      # Updates:[
      # email, connectkey1.5.14, Lifecycle Manager 2.0.12, ds750hotfix3
      #
      # ]<br />
      #
      # with different OS variants like e.g.:
      #
      # Version 6.6.1.C1.801 Windows (Build 6.6.1.C1.801)<br />

      vers_pattern = "Version ([0-9.]+[^ ]*) [^<]+<";
      # nb: Using it like this to make the check a little bit more strict...
      vers = egrep( pattern:"^\s*" + vers_pattern, string:res, icase:FALSE );
      vers = eregmatch( pattern:vers_pattern, string:vers, icase:FALSE );
      if( vers[1] ) {

        # Only overwrite / add the info if the version is "unknown". See note on the OS detection
        # above why this is done like this.
        if( version == "unknown" )
          version = vers[1];

        # but we're still adding it to the concluded reporting independent from that...
        concluded += '\n  ' + vers[0];
        conclUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only: TRUE );

        # nb: If we have the OS info register a generic OS...
        if( "Linux" >< vers[0] )
          os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:port, banner_type:"Xerox DocuShare About Page", banner:vers[0], desc:SCRIPT_DESC, runs_key:"unixoide" );
        else if( "Windows" >< vers[0] )
          os_register_and_report( os:"Windows", cpe:"cpe:/o:microsoft:windows", port:port, banner_type:"Xerox DocuShare About Page", banner:vers[0], desc:SCRIPT_DESC, runs_key:"windows" );
      }
    }

    # nb: The CVE from 2019 is using the first CPE while the one from 2014 the latter...
    cpe1 = build_cpe( value:tolower( version ), exp:"^([0-9.a-z]+)", base:"cpe:/a:fujixerox:docushare:" );
    cpe2 = build_cpe( value:tolower( version ), exp:"^([0-9.a-z]+)", base:"cpe:/a:xerox:docushare:" );
    if( ! cpe1 ) {
      cpe1 = "cpe:/a:fujixerox:docushare";
      cpe2 = "cpe:/a:xerox:docushare";
    }

    register_product( cpe:cpe1, location:install, port:port, service:"www" );
    register_product( cpe:cpe2, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Xerox DocuShare", version:version, install:install, cpe:cpe1,
                                              concluded:concluded, concludedUrl:conclUrl ),
                 port:port );
    exit( 0 );
  }
}

exit( 0 );
