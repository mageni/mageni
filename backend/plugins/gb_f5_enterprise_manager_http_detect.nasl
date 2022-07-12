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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105305");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2021-05-27T09:46:37+0000");
  script_tag(name:"last_modification", value:"2021-05-27 10:33:26 +0000 (Thu, 27 May 2021)");
  script_tag(name:"creation_date", value:"2015-06-24 14:01:02 +0200 (Wed, 24 Jun 2015)");
  script_name("F5 Enterprise Manager Configuration Utility Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the F5 Enterprise Manager Configuration
  Utility.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");

port = http_get_port( default:443 );

url = "/tmui/tmui/login/welcome.jsp";
install = "/tmui/";

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<title>BIG-IP" >< buf && "Welcome to the Enterprise Manager Configuration Utility" >< buf ) {

  cpe = "cpe:/a:f5:enterprise_manager";

  set_kb_item( name:"f5/enterprise_manager/configuration_utillity", value:TRUE );
  set_kb_item( name:"f5/enterprise_manager/configuration_utillity/port", value:port );
  set_kb_item( name:"f5/enterprise_manager/detected", value:TRUE );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  # From https://support.f5.com/csp/article/K121:
  # CentOS Linux
  os_register_and_report( os:"CentOS", cpe:"cpe:/o:centos:centos", port:port, desc:"F5 Enterprise Manager Configuration Utility Detection (HTTP)", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"F5 Enterprise Manager Configuration Utility",
                                            version:"unknown",
                                            install:install,
                                            cpe:cpe,
                                            concluded:"/tmui/tmui/login/welcome.jsp" ),
               port:port );
}

exit( 0 );