###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_sun_opensso_detect.nasl 10859 2018-08-09 11:49:23Z cfischer $
#
# Sun/Oracle OpenSSO Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Updated to detect new versions.
# Kashinath T <tkashinath@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.900817");
  script_version("$Revision: 10859 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-09 13:49:23 +0200 (Thu, 09 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_name("Sun/Oracle OpenSSO Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Sun/Oracle OpenSSO.
  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

foreach dir( make_list( "/", "/opensso", "/sso" ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  res = http_get_cache( item:dir + "/UI/Login.jsp", port:port );

  if( "OpenSSO" >< res && "X-DSAMEVersion" >< res && egrep( pattern:"^HTTP/1\.[01] 200", string:res ) ) {

    cpe = "cpe:/a:oracle:opensso";
    version = "unknown";
    set_kb_item( name:"Oracle/OpenSSO/detected", value:TRUE );
    set_kb_item( name:"JavaSysAccessManger_or_OracleOpenSSO/detected", value:TRUE );

    # X-DSAMEVersion: Oracle OpenSSO 8.0 Update 2 Build 6.1(2010-July-20 01:15)
    # X-DSAMEVersion: Oracle OpenSSO 8.0 Update 2 Patch3 Build 6.1(2011-June-8 05:24)
    # X-DSAMEVersion: Enterprise 8.0 Build 6(2008-October-31 09:07)
    # nb: "Snapshot Build" is probably from OpenAM: X-DSAMEVersion: Snapshot Build 9.5.1_RC2(2010-September-16 12:02)
    vers = eregmatch( pattern:"X-DSAMEVersion:( Enterprise | Snapshot Build | Oracle OpenSSO )?([0-9]\.[0-9.]+([a-zA-Z0-9 ]+)?)", string:res );
    if( ! isnull( vers[2] ) ) {
      concluded = vers[0];
      version = ereg_replace( pattern:" ", string:vers[2], replace:"." );
      cpe += ":" + version;
      tmp_version = version + " under " + install;
      set_kb_item( name:"www/"+ port + "/Sun/OpenSSO", value:tmp_version );
    }

    register_product( cpe:cpe, location:install, port:port, service:"www" );

    log_message( data:build_detection_report( app:"Sun/Oracle OpenSSO",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:concluded ),
                                              port:port );
    exit( 0 );
  }
}

exit( 0 );