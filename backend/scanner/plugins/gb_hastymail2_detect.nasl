###############################################################################
# OpenVAS Vulnerability Test
#
# Hastymail2 Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801575");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2019-05-13T14:05:09+0000");
  script_tag(name:"last_modification", value:"2019-05-13 14:05:09 +0000 (Mon, 13 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Hastymail2 Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script detects the version of Hastymail2 on remote host
  and sets the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/Hastymail2", "/hastymail2", "/hastymail","/hm2", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( "Login | Hastymail2<" >< rcvRes && "Hastymail Development Group" >< rcvRes ) {

    version = "unknown";

    sndReq = http_get( item: dir + "/UPGRADING", port:port );
    rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

    ## Match the version
    ver = eregmatch( pattern:"to (([a-zA-z]+)?([0-9.]+)( (RC[0-9]))?)", string:rcvRes );

    if( ver[1] != NULL && ver[2] != NULL ) {
      version = ver[1];
    } else if( ver[3] != NULL && ver[2] == NULL ) {
      version = ver[3];
    }

    if( "RC" >< ver[5] ) version = version + ' ' + ver[5];

    tmp_version = version + " under " + install;
    set_kb_item( name:"www/" + port + "/Hastymail2", value: tmp_version );
    set_kb_item( name:"hastymail2/detected", value: TRUE );

    if( version != "unknown" ) {
      cpe = "cpe:/a:hastymail:hastymail2:" + version;
    } else {
      cpe = "cpe:/a:hastymail:hastymail2";
    }

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"Hastymail2",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );
