# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106905");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2017-06-23 15:38:36 +0700 (Fri, 23 Jun 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Trihedral VTScada Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");

  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Trihedral VTScada.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:80 );

res = http_get_cache( port:port, item:"/" );

if ( "Server: VTScada" >!< res || res !~ "Location: /.*/anywhere/Page" )
  exit( 0 );

url = eregmatch( pattern:"Location: ((.*)/anywhere/Page)", string:res );
if ( isnull( url[1] ) )
  exit( 0 );

location = url[2];
url = url[1];

conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req );

if ( res =~ '<title( id="[a-zA-Z]+")?>VTScada Anywhere (login|Client)</title>' ) {
  version = "unknown";

  vers = eregmatch( pattern:"anywhereClientServerVersion='([0-9.]+)", string:res );
  if ( ! isnull( vers[1] ) ) {
    version = vers[1];
    concluded += "  " + vers[0];
  }

  set_kb_item( name:"trihedral/vtscada/detected", value:TRUE );
  set_kb_item( name:"trihedral/vtscada/http/detected", value:TRUE );

  set_kb_item( name:"trihedral/vtscada/http/" + port + "/installs",
               value:port + "#---#Trihedral Engineering Limited VTScada#---#" + location + "#---#" + version + "#---#" + concluded + "#---#" + conclurl );

  exit( 0 );
}

exit( 0 );
