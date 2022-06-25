# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108751");
  script_version("2020-04-17T12:25:37+0000");
  script_tag(name:"last_modification", value:"2020-04-20 08:28:46 +0000 (Mon, 20 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-17 11:38:17 +0000 (Fri, 17 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("CentOS WebPanel (CWP) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2030, 2082, 2083, 2086, 2087);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://centos-webpanel.com/");

  script_tag(name:"summary", value:"Detection of CentOS WebPanel (CWP).

  The script sends a connection request to the server and attempts to detect CentOS WebPanel (CWP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:2030 );

res = http_get_cache( port:port, item:"/" );
res2 = http_get_cache( port:port, item:"/login/index.php" );

if( res =~ "Server\s*:\s*cwpsrv" || res2 =~ "Server\s*:\s*cwpsrv" ||
    # <strong>powered by</strong></font><strong> CentOS-WebPanel.com</strong></h1>
    # alt="[ Powered by CentOS-WebPanel ]"></a>
    # <title>HTTP Server Test Page powered by CentOS-WebPanel-apache.com</title>
    egrep( string:res, pattern:"Powered by.* CentOS-WebPanel", icase:TRUE ) ||
    ( "<title>CWP | User</title>" >< res && "cwp_theme" >< res ) ||
    res =~ '<a href="https?://(www\\.)?control-webpanel\\.com" target="_blank">CWP Control WebPanel\\.</a>' ||
    res2 =~ '<a href="https?://(www\\.)?centos-webpanel\\.com" target="_blank">CentOS WebPanel</a>' ||
    "<title>Login | CentOS WebPanel</title>" >< res2 ) {

  version = "unknown";
  cpe = "cpe:/a:centos-webpanel:centos_web_panel";

  set_kb_item( name:"centos_webpanel/detected", value:TRUE );

  # nb: Only runs on these two OS variants
  register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", desc:"CentOS WebPanel (CWP) Detection (HTTP)", runs_key:"unixoide" );
  register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", desc:"CentOS WebPanel (CWP) Detection (HTTP)", runs_key:"unixoide" );

  register_product( cpe:cpe, location:"/", port:port, service:"www" );

  log_message( data:build_detection_report( app:"CentOS WebPanel (CWP)",
                                            version:version,
                                            install:"/",
                                            cpe:cpe ),
               port:port );
}

exit( 0 );
