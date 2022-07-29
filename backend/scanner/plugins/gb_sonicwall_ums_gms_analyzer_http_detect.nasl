# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107120");
  script_version("2022-07-26T10:10:42+0000");
  script_tag(name:"last_modification", value:"2022-07-26 10:10:42 +0000 (Tue, 26 Jul 2022)");
  script_tag(name:"creation_date", value:"2017-01-11 10:12:05 +0700 (Wed, 11 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SonicWall Global Management System (GMS) / Universal Management Suite (USM) / Analyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Dell SonicWALL Global Management System (GMS) /
  Universal Management Suite (USM) / Analyzer.");

  script_xref(name:"URL", value:"https://www.sonicwall.com/products/management-and-reporting/global-management-system/");
  script_xref(name:"URL", value:"https://www.sonicwall.com/products/management-and-reporting/network-analyzer/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );
url1 = "/";
res = http_get_cache( item:url1, port:port );

# nb: Only major version, no minor, no build. Not usable for version based VTs
if( res =~ "<TITLE>(Dell )?SonicWALL Universal Management Suite" ) {
  version = "unknown";
  install = "/";

  url2 = "/sgms/auth";
  res1 = http_get_cache( port:port, item:url2 );

  if( res1 =~ "<title>(Dell)?(SonicW(ALL|all) )?(GMS|Global Management System)( [0-9.]+)? Login" ) {
    product = "Global Management System";
    cpe_part = "global_management_system";

    set_kb_item( name:"sonicwall/gms/detected", value:TRUE );
    set_kb_item( name:"sonicwall/gms/http/detected", value:TRUE );

    concUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );

    # <div class="version">Global Management System&nbsp;8.6</div>
    vers = eregmatch( pattern:'"version">[^;]+;([0-9.]+)<', string:res1 );
    if( ! isnull( vers[1] ) ) {
      version = vers[1];
    } else {
      # <title>Global Management System 9.2 Login</title>
      vers = eregmatch( pattern:"Global Management System ([0-9.]+) Login", string:res1 );
      if( ! isnull( vers[1] ) )
        version = vers[1];
    }
  } else if( res1 =~ "<title>(Dell )?SonicW(ALL|all) Analyzer Login</title>" ) {
    product = "Analyzer";
    cpe_part = "analyzer";

    set_kb_item( name:"sonicwall/analyzer/detected", value:TRUE );
    set_kb_item( name:"sonicwall/analyzer/http/detected", value:TRUE );

    concUrl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
    # <div class="version">Analyzer&nbsp;8.4</div>
    vers = eregmatch( pattern:'"version">[^;]+;([0-9.]+)<', string:res1 );
    if( ! isnull( vers[1] ) )
      version = vers[1];
  } else {
    url3 = "/appliance/login";
    res2 = http_get_cache( port:port, item:url3 );
    if( res2 =~ "<title>(Dell )?SonicW(ALL|all) Universal Management (Appliance|Host) Login</title>" ) {
      product = "Global Management System Appliance";
      cpe_part = "global_management_system";

      set_kb_item( name:"sonicwall/gms/detected", value:TRUE );
      set_kb_item( name:"sonicwall/gms/http/detected", value:TRUE );

      concUrl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
      # <div class="version"><script type="text/javascript">document.writeln(productName);</script>&nbsp;8.7</div>
      vers = eregmatch( pattern:'"version">.+&nbsp;([0-9.]+)<', string:res2 );
      if( ! isnull( vers[1] ) )
        version = vers[1];
    } else {
      product = "Universal Management Suite";
      cpe_part = "universal_management_suite";

      concUrl = http_report_vuln_url( port:port, url:url1, url_only:TRUE );

      # <TITLE>SonicWall Universal Management Suite v9.1</TITLE>
      vers = eregmatch( pattern:"<TITLE>(Dell )?SonicWALL Universal Management Suite v([0-9.]+)</TITLE>",
                        string:res, icase: TRUE );
      if( ! isnull(vers[2] ) )
        version = vers[2];
    }
  }

  set_kb_item( name:"sonicwall/ums/detected", value:TRUE );
  set_kb_item( name:"sonicwall/ums/http/detected", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sonicwall:" + cpe_part + ":" );
  if( ! cpe )
    cpe = "cpe:/a:sonicwall:" + cpe_part;

  os_register_and_report( os:"SonicWall SonicOS", cpe:"cpe:/o:sonicwall:sonicos",
                          desc:"SonicWall Global Management System (GMS) / Universal Management Suite (USM) / Analyzer Detection (HTTP)",
                          runs_key:"unixoide" );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"SonicWALL " + product, version:version, install:install,
                                            cpe:cpe, concluded:vers[0], concludedUrl:concUrl ),
               port:port );
  exit( 0 );
}

exit( 0 );
