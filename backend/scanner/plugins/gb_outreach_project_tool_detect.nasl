###############################################################################
# OpenVAS Vulnerability Test
#
# Outreach Project Tool Version Detection (OPT)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801069");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-08 05:49:24 +0100 (Tue, 08 Dec 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Outreach Project Tool Version Detection (OPT)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed Outreach Project Tool version and
  saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/OPT127MAX/opt", "/opt", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  sndReq = http_get( item:dir + "/index.php?OPT_Session=VT_Req", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  if( "<title>Outreach Project Tool Login</title>" >< rcvRes || "./include/opt_css.php" >< rcvRes ||
      'src="main_menu/brief_help/' >< rcvRes || 'src="main_menu/status/"' >< rcvRes ) {

    version = "unknown";

    sndReq = http_get( item: dir + "/include/init_OPT_lib.txt", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if( ! isnull( rcvRes ) && ( ver = egrep( pattern:"CRM_ver.*", string:rcvRes ) ) ) {
      ver = eregmatch( pattern:"([0-9.]+)", string:ver );
      if( ver[1] != NULL ) version = ver[1];
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/OPT", value:tmp_version );
    set_kb_item( name:"outreach_project_tool/detected", value:TRUE );

    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:lanifex:outreach_project_tool:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:lanifex:outreach_project_tool';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Outreach Project Tool",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );
