###############################################################################
# OpenVAS Vulnerability Test
#
# HP Integrated Lights-Out Detection
#
# Authors:
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Modifications by Tenable :
# - Description
# Modifications by Daniel Reich <me at danielreich dot com>
# - Added detection for HP Remote Insight ILO Edition II
# - Removed &copy; in original string, some versions flip the
#   order of Copyright and &copy;
#
# Copyright:
# Copyright (C) 2006 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.20285");
  script_version("2019-04-10T08:02:39+0000");
  script_tag(name:"last_modification", value:"2019-04-10 08:02:39 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("HP Integrated Lights-Out Detection");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2006 David Maciejak");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:443 );
r = http_get_cache( item:"/", port:port );
if( isnull( r ) ) exit( 0 );

if ((r =~ "(<title>HP iLO Login</title>|<title>iLO [0-9]+</title>)" &&
     "Hewlett-Packard Development Company" >< r) ||
    ("HP Integrated Lights-Out" >< r &&
     egrep(pattern: "Copyright .+ Hewlett-Packard Development Company", string: r)) ||
    ("<title>HP Remote Insight<" >< r && egrep(pattern: "Hewlett-Packard Development Company", string: r)) ||
    (r =~ ">HP Integrated Lights-Out [0-9]+ Login<" && r =~ "Copyright.*Hewlett Packard Enterprise Development") ||
    "Server: HP-iLO-Server" >< r || "Server: HPE-iLO-Server" >< r ||
    ("iLO.getSVG" >< r && "iLO.getCookie" >< r) ||
    ("EVT_ILO_RESET_PULSE" >< r && "iLOGlobal" >< r)) {

  fw_vers  = "unknown";
  ilo_vers = "unknown";
  sso      = 0;
  install  = "/";

  url = '/xmldata?item=All';
  req = http_get( item:url, port:port );
  buf = http_send_recv( port:port, data:req, bodyonly:TRUE );

  if( "Integrated Lights-Out" >< buf ) {

    conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

    fw_version = eregmatch( pattern:"<FWRI>([^<]+)</FWRI>", string:buf );
    if( ! isnull( fw_version[1] ) ) fw_vers = fw_version[1];

    if( "<PN>Integrated Lights-Out (iLO)</PN>" >< buf ) {
      ilo_vers = 1;
    } else {
      ilo_version = eregmatch( pattern:"<PN>Integrated Lights-Out ([0-9]+) [^<]+</PN>", string:buf );
      if( ! isnull( ilo_version[1] ) ) ilo_vers = int( ilo_version[1] );
    }

    _sso = eregmatch( pattern:"<SSO>(0|1)</SSO>", string:buf );
    if( ! isnull( _sso[1] ) ) {
      sso = int( _sso[1] );
      extra = "SSO Status: " + _sso[0];
    }
  }

  if( ilo_vers == "unknown" && r =~ "<title>iLO [0-9]+</title>" ) {
    ilo_version = eregmatch( pattern:"<title>iLO ([0-9]+)</title>", string:r );
    if( ! isnull( ilo_version[1] ) ) ilo_vers = int( ilo_version[1] );
  }

  if( fw_vers == "unknown" || ilo_vers == "unknown" ) {

    url = "/json/login_session";
    req = http_get( item:url, port:port );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( '{"secjmp' >< buf ) {

      conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );

      if( fw_vers == "unknown" ) {
        fw_version = eregmatch( pattern:'version":"([^"]+)"', string:buf );
        if( ! isnull( fw_version[1] ) ) fw_vers = fw_version[1];
      }

      if( ilo_vers == "unknown" ) {
        # "PRODGEN":"iLO 4",
        ilo_version = eregmatch( pattern:'"PRODGEN":"iLO ([0-9]+)",', string:buf );
        if( ! isnull( ilo_version[1] ) ) ilo_vers = int( ilo_version[1] );
      }
    }
  }

  cpe = "cpe:/o:hp:integrated_lights-out";

  if( ilo_vers != "unknown" ) {
    app_name = "HP Integrated Lights-Out Generation " + ilo_vers + " Firmware";
    concluded += ilo_version[0];
    cpe += "_" + ilo_vers + "_firmware";
  } else {
    app_name = "HP Integrated Lights-Out Unknown Generation Firmware";
    cpe += "_unknown_firmware";
  }

  if( fw_vers != "unknown" ) {
    if( concluded ) concluded += '\n';
    concluded += fw_version[0];
    cpe += ':' + fw_vers;
  }

  set_kb_item( name:"www/" + port + "/HP_ILO/fw_version", value:fw_vers );
  set_kb_item( name:"www/" + port + "/HP_ILO/ilo_version", value:ilo_vers );
  set_kb_item( name:"www/" + port + "/HP_ILO/sso", value:sso );
  set_kb_item( name:"HP_ILO/installed", value:TRUE );

  register_and_report_os( os:app_name, cpe:cpe, desc:"HP Integrated Lights-Out Detection", runs_key:"unixoide" );

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:app_name,
                                            version:fw_vers,
                                            install:install,
                                            cpe:cpe,
                                            concluded:concluded,
                                            concludedUrl:conclUrl,
                                            extra:extra ),
               port:port );
  exit(0);
}

exit( 0 );
