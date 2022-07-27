###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dsl_detect.nasl 12266 2018-11-08 16:05:51Z cfischer $
#
# D-Link DSL Devices Detection
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812377");
  script_version("$Revision: 12266 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 17:05:51 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-01-03 16:00:40 +0530 (Wed, 03 Jan 2018)");
  script_name("D-Link DSL Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("D-LinkDSL/banner");

  script_tag(name:"summary", value:"Detection of D-Link DSL Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a D-Link DSL device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach url( make_list( "/", "/cgi-bin/webproc" ) ) {

  buf = http_get_cache( port:port, item:url );

  # Server: Linux, WEBACCESS/1.0, DSL-2890AL Ver AU_1.02.10
  if( "Server: micro_httpd" >!< buf && "Server: Boa" >!< buf && "Server: Linux," >!< buf && "Server: RomPager/" >!< buf )
    continue;

  # NOTE: Those are NO D-Link but Asus Routers:
  # WWW-Authenticate: Basic realm="DSL-N10"
  # WWW-Authenticate: Basic realm="DSL-N14U"
  # They have a separate "Server: httpd" banner which is skipped above.
  #
  # NOTE2: There are also a few with the following out:
  # WWW-Authenticate: Basic realm="DSL Router"
  # Server: micro_httpd
  # Those are very unlikely D-Link devices...

  # <div class="pp">Product Page : DSL-2890AL<a href="javascript:check_is_modified('http://support.dlink.com/')"><span id="model" align="left"></span></a></div>
  if( 'WWW-Authenticate: Basic realm="DSL-([0-9A-Z]+)' >< buf || "<title>D-Link DSL-" >< buf ||
      ( "D-Link" >< buf && ( "Product Page : DSL-" >< buf || "Server: Linux, WEBACCESS/1.0, DSL-" >< buf ) ) ||
      ( "DSL Router" >< buf && buf =~ "Copyright.*D-Link Systems" ) ) {

    set_kb_item( name:"Host/is_dlink_dsl_device", value:TRUE );
    set_kb_item( name:"Host/is_dlink_device", value:TRUE );

    conclUrl   = report_vuln_url( port:port, url:url, url_only:TRUE );
    fw_version = "unknown";
    os_app     = "D-Link DSL";
    os_cpe     = "cpe:/o:d-link:dsl";
    hw_version = "unknown";
    hw_app     = "D-Link DSL";
    hw_cpe     = "cpe:/h:d-link:dsl";
    model      = "unknown";
    install    = "/";

    mo = eregmatch( pattern:"(Product Page ?: ?|Server: Linux, WEBACCESS/1\.0, )?DSL-([0-9A-Z]+)", string:buf );
    if( mo[2] ) {
      model    = mo[2];
      os_concl = mo[0];
      hw_concl = mo[0];
      os_app += "-" + model + " Firmware";
      os_cpe += "-" + tolower( model ) + "_firmware";
      hw_app += "-" + model + " Device";
      hw_cpe += "-" + tolower( model );
      set_kb_item( name:"d-link/dsl/model", value:model );
    } else {
      os_app += " Unknown Model Firmware";
      os_cpe += "-unknown_model_firmware";
      hw_app += " Unknown Model Device";
      hw_cpe += "-unknown_model";
    }

    # <div class="fwv">Firmware Version : AU_1.02.06<span id="fw_ver" align="left"></span></div>
    fw_ver = eregmatch( pattern:'Firmware Version ?: (AU_|V)?([0-9.]+)', string:buf );
    if( fw_ver[2] ) {
      fw_version = fw_ver[2];
      os_cpe    += ":" + fw_version;
      set_kb_item( name:"d-link/dsl/fw_version", value:fw_version );
      if( os_concl )
        os_concl += '\n';
      os_concl += fw_ver[0];
    }

    if( fw_version == "unknown" ) {
      # nb: Not available on all DSL- devices
      url2   = "/ayefeaturesconvert.js";
      req    = http_get( port:port, item:url2 );
      res    = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
      fw_ver = eregmatch( string:res, pattern:'var AYECOM_FWVER="([0-9]\\.[0-9]+)";' );
      if( fw_ver[1] ) {
        fw_version = fw_ver[1];
        os_cpe    += ":" + fw_version;
        set_kb_item( name:"d-link/dsl/fw_version", value:fw_version );
        if( conclUrl )
          conclUrl += '\n';
        conclUrl += report_vuln_url( port:port, url:url2, url_only:TRUE );
        if( os_concl )
          os_concl += '\n';
        os_concl += fw_ver[0];
      }
    }

    # <div class="hwv">Hardware Version : A1<span id="hw_ver" align="left"></span></div>
    hw_ver = eregmatch( pattern:'>Hardware Version ?: ([0-9A-Za-z.]+)', string:buf );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
      hw_cpe    += ":" + tolower( hw_version );
      set_kb_item( name:"d-link/dsl/hw_version", value:hw_version );
      if( hw_concl )
        hw_concl += '\n';
      hw_concl += hw_ver[0];
    }

    register_and_report_os( os:os_app, cpe:os_cpe, banner_type:"D-Link DSL Device Login Page/Banner", port:port, desc:"D-Link DSL Devices Detection", runs_key:"unixoide" );
    register_product( cpe:os_cpe, location:install, port:port, service:"www" );
    register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

    report = build_detection_report( app:os_app,
                                     version:fw_version,
                                     concluded:os_concl,
                                     concludedUrl:conclUrl,
                                     install:install,
                                     cpe:os_cpe );

    report += '\n\n' + build_detection_report( app:hw_app,
                                               version:hw_version,
                                               concluded:hw_concl,
                                               install:install,
                                               cpe:hw_cpe );

    log_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 0 );