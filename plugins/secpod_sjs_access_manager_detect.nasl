###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sjs_access_manager_detect.nasl 10859 2018-08-09 11:49:23Z cfischer $
#
# Sun Java System Access Manager Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900194");
  script_version("$Revision: 10859 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 13:49:23 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Sun Java System Access Manager Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script detects the installed version of Access Manager and
  sets the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

foreach dir( make_list( "/", "/amserver" ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/UI/Login.jsp", port:port );

  if( egrep( pattern:"Sun Java System Access Manager .*", string:res ) &&
      egrep( pattern:"^HTTP/1\.[01] 200", string:res ) ) {

    version = "unknown";
    set_kb_item( name:"Sun/JavaSysAccessManger/detected", value:TRUE );
    set_kb_item( name:"JavaSysAccessManger_or_OracleOpenSSO/detected", value:TRUE );

    vers = eregmatch( pattern:"X-DSAMEVersion: ([0-9]\.[0-9.]+(.?[a-zQ0-9]+)?)", string:res );
    if( ! isnull( vers[1] ) ) {
      concluded = vers[0];
      vers = ereg_replace( pattern:" ", string:vers[1], replace:"." );
      tmp_version = vers + " under " + install;
      set_kb_item( name:"www/"+ port + "/Sun/JavaSysAccessManger", value:tmp_version );
    }

    cpe = build_cpe( value:version, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:sun:java_system_access_manager:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:sun:java_system_access_manager";

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Sun Java System Access Manager",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concluded ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );