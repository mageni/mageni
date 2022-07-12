###############################################################################
# OpenVAS Vulnerability Test
#
# Trend Micro Interscan Web Security Virtual Appliance Detection (HTTP) Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140242");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-07-08T05:53:09+0000");
  script_tag(name:"last_modification", value:"2020-07-08 14:19:02 +0000 (Wed, 08 Jul 2020)");
  script_tag(name:"creation_date", value:"2017-04-10 16:22:10 +0200 (Mon, 10 Apr 2017)");

  script_name("Trend Micro Interscan Web Security Virtual Appliance Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the Trend Micro Interscan Web Security Virtual Appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:8443 );

buf = http_get_cache( port:port, item:"/logon.jsp" );

if( "<title>Trend Micro InterScan Web Security Virtual Appliance</title>" >< buf && "uilogonsubmit.jsp" >< buf ) {
  version = "unknown";
  build = "unknown";

  set_kb_item( name:"trendmicro/IWSVA/detected", value:TRUE );
  set_kb_item( name:"trendmicro/IWSVA/http/detected", value:TRUE );
  set_kb_item( name:"trendmicro/IWSVA/http/port", value:port );

  url = "/html/about.htm";
  res = http_get_cache( port:port, item:url );
  # <td  class="popup-title">About Trend Micro InterScan Web Security Virtual Appliance 6.5 </td>
  vers = eregmatch( pattern:"Trend Micro InterScan Web Security Virtual Appliance ([0-9.]+)", string:res );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    set_kb_item( name:"trendmicro/IWSVA/http/" + port + "/concluded", value:vers[0] );
    set_kb_item( name:"trendmicro/IWSVA/http/" + port + "/concludedUrl",
                 value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );
  }

  set_kb_item( name:"trendmicro/IWSVA/http/" + port + "/version", value:version );
  set_kb_item( name:"trendmicro/IWSVA/http/" + port + "/build", value:build );
}

exit( 0 );
