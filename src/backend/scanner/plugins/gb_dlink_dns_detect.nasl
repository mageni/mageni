###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dns_detect.nasl 12265 2018-11-08 15:57:01Z cfischer $
#
# D-Link DNS NAS Devices Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106015");
  script_version("$Revision: 12265 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 16:57:01 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-07-10 14:32:27 +0700 (Fri, 10 Jul 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("D-Link DNS NAS Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("D-LinkDNS/banner");

  script_tag(name:"summary", value:"Detection of D-Link DNS NAS Devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a D-Link DNS NAS device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

fw_version = "unknown";
os_app     = "D-Link DNS";
os_cpe     = "cpe:/o:d-link:dns";
hw_version = "unknown";
hw_app     = "D-Link DNS";
hw_cpe     = "cpe:/h:d-link:dns";
model      = "unknown";
install    = "/";

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

# DNS-320, DNS-320L, DNS-325, DNS-327L, DNS-345
if( "Server: lighttpd/" >< banner ) {

  res = http_get_cache( item:"/", port:port );
  if( ! res ) exit( 0 );

  # "ShareCenter by D-Link" Logo on e.g. DNS-325, previous versions of this Detection-VT has
  # only checked for a "ShareCenter" string which might not be there on different firmware versions.
  logo_identified = FALSE;
  logo_url = "/web/images/logo.png";
  if( logo_url >< res ) {
    req  = http_get( item:logo_url, port:port );
    res2 = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( res2 && hexstr( MD5( res2 ) ) == "0b5e6b0092c45768fbca24706bc9e08d" )
      logo_identified = TRUE;
  }

  if( "Please Select Your Account" >< res && ( "ShareCenter" >< res || logo_identified ) ) {

    found = TRUE;

    url = "/xml/info.xml";
    res = http_get_cache( item:url, port:port );

    if( res =~ "<info>" && res =~ "www.dlink.com" ) {

      # <hw_ver>DNS-325</hw_ver>
      mo = eregmatch( pattern:"<hw_ver>DNS-(.*)</hw_ver>", string:res );
      if( mo[1] ) {
        model = mo[1];
        concluded = mo[0];
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

      # <version>1.00</version>
      fw_ver = eregmatch( pattern:"<version>(.*)</version>", string:res );
      if( fw_ver[1] ) {
        os_cpe    += ":" + fw_ver[1];
        fw_version = fw_ver[1];
        set_kb_item( name:"d-link/dsl/fw_version", value:fw_version );
        if( concluded )
          concluded += '\n';
        concluded += fw_ver[0];
      }
      if( fw_version != "unknown" || model != "unknown" )
        conclUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    if( model == "unknown" ) {
      os_app += " Unknown Model Firmware";
      os_cpe += "-unknown_model_firmware";
      hw_app += " Unknown Model Device";
      hw_cpe += "-unknown_model";
    }
  }
}

# TODO: At least the check here seems to be quite unreliable, this should be updated if possible...
# DNS-321, DNS-323, DNS-343
else if ("Server: GoAhead-Webs" >< banner ) {

  res = http_get_cache( item:"/web/login.asp", port:port );

  if( egrep( string:res, pattern:"<TITLE>dlink(.*)?</TITLE>", icase:TRUE ) && "D-Link Corporation/D-Link Systems, Inc." >< res ) {
    found = TRUE;
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    os_cpe += "-unknown_model";
  }
}

if( found ) {

  set_kb_item( name:"Host/is_dlink_dns_device", value:TRUE );
  set_kb_item( name:"Host/is_dlink_device", value:TRUE );

  register_and_report_os( os:os_app, cpe:os_cpe, banner_type:"D-Link DNS Device Login Page", port:port, desc:"D-Link DNS Devices Detection", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app,
                                   version:fw_version,
                                   concludedUrl:conclUrl,
                                   concluded:concluded,
                                   install:install,
                                   cpe:os_cpe );

  report += '\n\n' + build_detection_report( app:hw_app,
                                             skip_version:TRUE,
                                             install:install,
                                             cpe:hw_cpe );

  log_message( port:port, data:report );
}

exit( 0 );