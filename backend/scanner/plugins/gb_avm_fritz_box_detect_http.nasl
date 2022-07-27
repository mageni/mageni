###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_detect_http.nasl 11412 2018-09-16 10:21:40Z cfischer $
#
# AVM FRITZ!Box Detection (HTTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.108036");
  script_version("$Revision: 11412 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-16 12:21:40 +0200 (Sun, 16 Sep 2018) $");
  script_tag(name:"creation_date", value:"2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script attempts to identify an AVM FRITZ!Box via the HTTP
  login page and tries to extract the model and version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

fingerprint["a39b0868ecce7916673a3119c164a268"] = "Fon WLAN;7240";
fingerprint["4ff79300a437d947adce1ecbc5dbcfe9"] = "Fon WLAN;7170";
fingerprint["9adfbf40db1a7594be31c21f28767363"] = "Fon WLAN;7270"; # The 7270, 7270v2 and 7270v3 have the same fingerprint

port = get_http_port( default:80 );
buf = http_get_cache( item:"/", port:port );

if( "FRITZ!Box" >< buf && ( "AVM" >< buf || "logincheck.lua" >< buf || "/cgi-bin/webcm" >< buf ) ) {

  set_kb_item( name:"avm_fritz_box/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/http/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/http/port", value:port );

  type       = "unknown";
  model      = "unknown";
  fw_version = "unknown";

  mo = eregmatch( pattern:'FRITZ!Box (Fon WLAN|WLAN)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)', string:buf );
  if( ! isnull( mo[1] ) ) type  = mo[1];
  if( ! isnull( mo[2] ) ) model = mo[2];

  if( type == "unknown" && model == "unknown" ) {
    req = http_get( port:port, item:"/css/default/images/kopfbalken_mitte.gif" );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
    if( ! isnull( res  ) ) {
      md5 = hexstr( MD5( res ) );
      if( fingerprint[md5] ) {
        tmp   = split( fingerprint[md5], sep:';', keep:FALSE );
        type  = tmp[0];
        model = tmp[1];
      }
    }
  }

  # Second try if the Box has no password set
  if( type == "unknown" && model == "unknown" ) {
    time = unixtime();
    postdata = "getpage=..%2Fhtml%2Fde%2Fmenus%2Fmenu2.html&errorpage=..%2Fhtml%2Findex.html" +
               "&var%3Alang=de&var%3Apagename=home&var%3Amenu=home" +
               "&time%3Asettings%2Ftime=" + time + "%2C-60";

    req = http_post_req( port:port, url:"/cgi-bin/webcm", data:postdata,
                         accept_header:"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                         add_headers:make_array( "Content-Type", "application/x-www-form-urlencoded",
                                                 "Upgrade-Insecure-Requests", "1",
                                                 "Referer", report_vuln_url( port:port, url:"/cgi-bin/webcm", url_only:TRUE ) ) );
    res = http_send_recv( port:port, data:req );

    if( res && res =~ "^HTTP/1\.[01] 200" && '<p class="ac">FRITZ!Box' >< res ) {

      #<p class="ac">FRITZ!Box Fon (UI), Firmware-Version 06.04.33</p>
      mo = eregmatch( pattern:'"ac">FRITZ!Box ([^\\(,]+).*Firmware-Version ([0-9.]+)<', string:res );
      if( ! isnull( mo[1] ) ) {
        mo_nd_type = eregmatch( pattern:'FRITZ!Box (Fon WLAN|WLAN|Fon)? ?([0-9]+( (v[0-9]+|vDSL|SL|LTE|Cable))?)?', string:mo[0] );
        if( ! isnull( mo_nd_type[1] ) ) type  = mo_nd_type[1];
        if( ! isnull( mo_nd_type[2] ) ) model = mo_nd_type[2];
      }

      if( ! isnull( mo[2] ) ) fw_version = mo[2];
    }
  }

  # Another try for newer models if the login page is unprotected
  # %26version%3D113.06.93%26subversion%3D
  if( fw_version == "unknown" ) {
    fw = eregmatch( pattern:"%26version%3D([0-9.]+)%26subversion%3D", string:buf );
    if( ! isnull( fw[1] ) ) fw_version = fw[1];
  }

  set_kb_item( name:"avm_fritz_box/http/" + port + "/type", value:type );
  set_kb_item( name:"avm_fritz_box/http/" + port + "/model", value:model );
  set_kb_item( name:"avm_fritz_box/http/" + port + "/firmware_version", value:fw_version );
}

exit( 0 );