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
  script_version("2022-03-07T15:18:51+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-08 11:27:32 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"creation_date", value:"2015-10-19 13:01:26 +0530 (Mon, 19 Oct 2015)");
  script_name("Jasig / Apereo Central Authentication Service (CAS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://apereo.github.io/cas");

  script_tag(name:"summary", value:"HTTP based detection of the Apereo (formerly Jasig) Central
  Authentication Service (CAS).");

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

foreach dir( make_list_unique( "/", "/cas", "/cas-server-webapp", http_cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/login";
  res = http_get_cache( item:url, port:port );
  if( ! res || res !~ "HTTP/1\.[01] 200" )
    continue;

  # e.g.:
  # >Powered by <a href="https://github.com/apereo/cas">Apereo CAS</a>
  # nb:
  # - Both products had the same 'login' and 'id="cas' string
  # - Login pages are often quite heavily customized so this currently might not catch all variants
  # - A few systems also had the "Powered by" string commented out or even removed
  # - Another one also didn't had the 'id="cas' but the HTML page title and cas.js was usable
  # - There was another one which had the "Powered by Apereo CAS" and only the .js file without the other pattern
  if( ( res =~ "Powered by[^>]+>(Jasig Central Authentication Service|Apereo CAS<)" &&
        ( "login" >< res && 'id="cas' >< res ) || res =~ 'src="[^>]*/js/cas\\.js[^>]*"></script>' ) ||
      (
        # nb: Just as an alternative fallback
        # <title>CAS - Central Authentication Service Login</title>
        # <title>CAS - Central Authentication Service</title>
        egrep( string:res, pattern:"^\s*<title>CAS - Central Authentication Service[^<]*</title>", icase:FALSE ) &&
        # src="/js/cas.js"></script>
        # src="/cas/themes/mytheme/js/cas.js"></script>
        # src="/js/cas.js?v=0"></script>
        res =~ 'src="[^>]*/js/cas\\.js[^>]*"></script>'
      )
    ) {

    version = "unknown";
    conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

    vers = eregmatch( pattern:">Jasig Central Authentication Service ([0-9.]+)", string:res );
    if( vers[1] )
      version = vers[1];

    # <code class="version">6.3.1 1/30/21, 1:41 AM</code>
    # <code class="version">6.3.7.4</code>
    if( version == "unknown" ) {
      vers = eregmatch( pattern:'"version">([0-9.]+)', string:res );
      if( vers[1] )
        version = vers[1];
    }

    set_kb_item( name:"jasig_apereo/cas/detected", value:TRUE );
    set_kb_item( name:"jasig_apereo/cas/http/detected", value:TRUE );

    # nb: The same product is currently tracked via different CPEs within the NVD...
    cpe1 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apereo:central_authentication_service:" );
    cpe2 = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apereo:cas_server:" );

    if( ! cpe1 ) {
      cpe1 = "cpe:/a:apereo:central_authentication_service";
      cpe2 = "cpe:/a:apereo:cas_server";
    }

    register_product( cpe:cpe1, location:install, port:port, service:"www" );
    register_product( cpe:cpe2, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Jasig / Apereo Central Authentication Service (CAS)",
                                              version:version,
                                              install:install,
                                              cpe:cpe1,
                                              concludedUrl:conclurl,
                                              concluded:vers[0] ),
                                              port:port );
  }
}

exit( 0 );
