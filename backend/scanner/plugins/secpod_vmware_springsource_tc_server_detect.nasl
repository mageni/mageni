##############################################################################
# OpenVAS Vulnerability Test
#
# Vmware SpringSource tc Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
################################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902187");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-14T12:12:41+0000");
  script_tag(name:"last_modification", value:"2019-05-14 12:12:41 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Vmware SpringSource tc Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Vmware SpringSource tc
  Server and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

foreach dir( make_list_unique( "/", "/myserver", "/SStc", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.html", port:port );

  if( "<title>SpringSource tc Server</title>"  >< rcvRes ) {

    version = "unknown";

    sndReq = http_get( item: dir + "/WEB-INFO/web.xml", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    if( "SpringSource tc Server runtime" >< rcvRes ) {

      ver = eregmatch( pattern:"tc Server runtime/(([0-9.]+).?([A-Za-z0-9-]+))?", string:rcvRes );
      ver = ereg_replace( pattern:"-", replace:".", string:ver[1] );
      if( ver != NULL ) version = ver;
    }

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/"+ port + "/Vmware/SSTC/Runtime", value:tmp_version );
    set_kb_item( name:"vmware/tc_server/detected", value:TRUE );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:vmware:tc_server:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:vmware:tc_server';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"SpringSource tc Server",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver ),
                                              port:port );
  }
}

exit( 0 );
