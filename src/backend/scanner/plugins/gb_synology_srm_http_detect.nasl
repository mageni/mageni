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
  script_oid("1.3.6.1.4.1.25623.1.0.170229");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-11-17 13:45:45 +0000 (Thu, 17 Nov 2022)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Synology Router / Router Manager (SRM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8001);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Synology router devices, Router
  Manager (SRM) OS and manager application.");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:8001 );

install = "/";

foreach url( make_list( "/webman/index.cgi", "/index.cgi" ) ) {
  buf = http_get_cache( item:url, port:port );
  # nb: old detection rules do not work anymore for newer versions
  if( buf =~ "SynologyRouter" && 'content="Synology Router' >< buf &&
      buf =~ "SYNO\.SDS\.Session" && buf =~ '<meta name="description" content="Synology Router provides a full-featured' ) {

    concl = "";
    version = "unknown";
    concUrl = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

    set_kb_item( name:"synology/srm/detected",value:TRUE );
    set_kb_item( name:"synology/srm/http/detected", value:TRUE );
    set_kb_item( name:"synology/srm/http/port", value:port );

    url1 = "/synohdpack/synohdpack.version";
    #majorversion="5"
    #minorversion="2"
    #buildphase="hotfix"
    #buildnumber="9346"
    #productversion="1.3.1"
    #smallfixnumber="1"
    #builddate="2022/08/19"
    #buildtime="09:03:59"
    res = http_get_cache( item:url1, port:port );
    if( res && res =~ "^HTTP/(1\.[01]|2) 200" ) {

      ver = eregmatch( pattern:'productversion="([0-9.]+)"', string:res );
      if( ! isnull( ver[1] ) ) {
        version = ver[1];
        concUrl += '\n  ' + http_report_vuln_url( port:port, url:url1, url_only:TRUE );
        concl += '\n  ' + ver[0];
      }
      # nb: we can add now build number and small fix number
      if( "unknown" >!< version ) {
        ver1 = eregmatch( pattern:'buildnumber="([0-9]+)"', string:res );
        if( ! isnull( ver1[1] ) ) {
          version += "-" + ver1[1];
          concl += '\n  ' + ver1[0];
        }

        ver2 = eregmatch( pattern:'smallfixnumber="([0-9]+)"', string:res );
        if( ! isnull( ver2[1] ) && int( ver2[1] ) > 0 ) {
          version += "-" + ver2[1];
          concl += '\n  ' + ver2[0];
        }
      }
    }

    url = "/webman/synodefs.cgi";
    res = http_get_cache( item:url, port:port );
    if( res && res =~ "^HTTP/(1\.[01]|2) 200" ) {

      # eg: "upnpmodelname":"DS3615xs"
      mod = eregmatch( pattern:'"upnpmodelname":"([a-zA-Z0-9+]+)"', string:res );
      if( ! isnull( mod[1] ) ) {
        set_kb_item( name:"synology/srm/http/" + port + "/model", value:mod[1] );
        concl += '\n  ' + mod[0];
        concUrl += '\n  ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    }

    set_kb_item( name:"synology/srm/http/" + port + "/version", value:version );

    if( concl )
      set_kb_item( name:"synology/srm/http/" + port + "/concluded", value:chomp( concl ) );

    if( concUrl )
      set_kb_item( name:"synology/srm/http/" + port + "/concludedUrl", value:concUrl );

    exit( 0 );
  }
}
exit( 0 );
