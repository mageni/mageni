###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine ADManager Plus Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107131");
  script_version("2019-05-17T10:38:54+0000");
  script_tag(name:"last_modification", value:"2019-05-17 10:38:54 +0000 (Fri, 17 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-19 16:11:25 +0530 (Thu, 19 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ManageEngine ADManager Plus Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "gb_manageengine_admanager_plus_detection_win.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of ManageEngine ADManager Plus.

  The script sends a HTTP connection request to the server and attempts to detect
  the presence of ManageEngine ADManager Plus and to extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

res = http_get_cache( item:"/", port:port );

if( res =~ "HTTP/1\.. 200" && ( "<title>ManageEngine" >< res && "ADManager Plus</title>" >< res ) &&
    '<input type="hidden" name="AUTHRULE_NAME" value="ADAuthenticator">' >< res &&
    "admp.login.browserinfo.message" >< res ) {

  set_kb_item( name:"manageengine/admanager_plus/installed", value:TRUE );

  version = "unknown";
  install = "/";

  vers = eregmatch( pattern:"style.css\?v\=([0-9]+)", string:res );
  if ( isnull ( vers[1] ) )
    vers = eregmatch( pattern:'ADMPAlert\\.js\\?v\\=([0-9]+)', string: res);

  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    version = version[0] + '.' + version[1] + '.' + version[2] + version[3];

    extra = "Build " + vers[1];
  }

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:manageengine:admanager_plus:" );

  if( ! cpe )
    cpe = 'cpe:/a:manageengine:admanager_plus';

  register_product( cpe:cpe, location:install, port:port, service:'www' );

  log_message( data:build_detection_report( app: "ManageEngine - ADManager Plus",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vers[0],
                                            extra:extra ),
               port:port );
}

exit( 0 );
