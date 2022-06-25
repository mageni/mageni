###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_dir_detect.nasl 13878 2019-02-26 12:22:09Z jschulte $
#
# D-Link DIR Devices Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103689");
  script_version("$Revision: 13878 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 13:22:09 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2013-04-08 13:52:56 +0200 (Mon, 08 Apr 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("D-Link DIR Devices Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "gb_hnap_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_mandatory_keys("D-LinkDIR/banner");

  script_tag(name:"summary", value:"Detection of D-Link DIR devices.

  The script sends a connection request to the server and attempts to
  determine if the remote host is a D-Link DIR device from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:8080 );
banner = get_http_banner( port:port );
if( ! banner )
  exit( 0 );

detected   = FALSE;
fw_version = "unknown";
os_app     = "D-Link DIR";
os_cpe     = "cpe:/o:d-link:dir";
hw_version = "unknown";
hw_app     = "D-Link DIR";
hw_cpe     = "cpe:/h:d-link:dir";
model      = "unknown";
install    = "/";

# Server: Linux, WEBACCESS/1.0, DIR-850L Ver 1.10WW
# Server: Linux, HTTP/1.1, DIR-850L Ver 1.09
# Server: Linux, WEBACCESS/1.0, DIR-850L Ver 1.10
# Server: Linux, HTTP/1.1, DIR-629 Ver 1.01CN
# Server: Linux, HTTP/1.1, DIR-600 Ver 2.17
if( _banner = egrep( string:banner, pattern:"(Server: Linux, (HTTP/1\.1|WEBACCESS/1\.0), DIR-[0-9]+[^ ]++ Ver|DIR-[0-9]+ web server)", icase:TRUE ) ) {

  detected = TRUE;
  _banner = chomp( _banner );
  fw_concluded = _banner;

  mo = eregmatch( pattern:" DIR-([0-9]+[^ ]*)", string:_banner );
  if( mo[1] ) {
    model = mo[1];
    os_app += "-" + model + " Firmware";
    os_cpe += "-" + tolower( model ) + "_firmware";
    hw_app += "-" + model + " Device";
    hw_cpe += "-" + tolower( model );
    set_kb_item( name:"d-link/dir/model", value:model );
  } else {
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "-unknown_model";
  }

  fw_ver = eregmatch( pattern:"Ver ([^\r\n]+)", string:_banner );
  if( fw_ver[1] ) {
    os_cpe    += ":" + fw_ver[1];
    fw_version = fw_ver[1];
    set_kb_item( name:"d-link/dir/fw_version", value:fw_version );
  }

  # nb: The "Firmware/Hardware Version" texts are sometimes translated into local languages. Few of the source code pattern has tabs in front as well.
  #
  # DIR-600:
  # <span class="version">Firmware Version : 2.17</span>
  # <span class="version">Hardware Version : Bx</span>
  #
  # DIR-850L:
  # <div class="fwv">Firmware Version : 1.05<span id="fw_ver" align="left"></span></div>
  # <div class="hwv">Hardware Version : A1<span id="hw_ver" align="left"></span></div>
  #
  # DIR-629:
  # <span class="version">???? : 1.01CN</span>
  # <span class="hwversion">???? : <span class="value" style="text-transform:uppercase;">A1</span></span>
  buf = http_get_cache( port:port, item:"/" );

  hw_ver = eregmatch( pattern:'Hardware Version : (<span class="value" style="text-transform:uppercase;">)?([^ <]+)<', string:buf );
  if( hw_ver[2] ) {
    hw_version = hw_ver[2];
  } else {
    hw_ver = eregmatch( pattern:'class="(hwv|hwversion)">.*([ABCDEIT][12])<', string:buf );
    if( hw_ver[2] )
      hw_version = hw_ver[2];
  }

  if( hw_version != "unknown" ) {
    hw_cpe    += ":" + tolower( hw_version );
    set_kb_item( name:"d-link/dir/hw_version", value:hw_version );
    hw_concluded = hw_ver[0];
    hw_conclurl  = report_vuln_url( port:port, url:"/", url_only:TRUE );
  }
}

if( "Server: Mathopd/" >< banner ) {

  url = "/";
  buf = http_get_cache( item:url, port:port );

  # <title>D-LINK SYSTEMS, INC | WIRELESS ROUTER | HOME</title>
  # <td><input type=text name="LOGIN_USER"></td>
  if( "<title>D-LINK" >< buf && "LOGIN_USER" >!< buf ) {
    url = "/index_temp.php";
    buf = http_get_cache( item:url, port:port );
  }

  if( "<title>D-LINK" >!< buf && "LOGIN_USER" >!< buf )
    exit( 0 );

  detected = TRUE;

  # target=_blank><font class=l_tb>DIR-615</font></a>
  mo = eregmatch( pattern:"class=l_tb>DIR-([^ <]+)<", string:buf );
  if( mo[1] ) {
    model = mo[1];
    fw_concluded = mo[0];
    os_app += "-" + model + " Firmware";
    os_cpe += "-" + tolower( model ) + "_firmware";
    hw_app += "-" + model + " Device";
    hw_cpe += "-" + tolower( model );
    set_kb_item( name:"d-link/dir/model", value:model );
  } else {
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "-unknown_model";
  }

  # DIR-615:
  # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;rev N24&nbsp;</td>
  # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;4.00&nbsp;</td>
  #
  # DIR-300:
  # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;rev A1&nbsp;</td>
  # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;1.06&nbsp;</td>
  #
  # DIR-605 with localization: (replace $localization with random name of the lanugage)
  # <td noWrap align="right">$localizations&nbsp;:&nbsp;rev 2A1&nbsp;</td>
  # <td noWrap align="right">$localizations&nbsp;:&nbsp;2.01&nbsp;</td>

  fw_ver = eregmatch( pattern:">Firmware Version&nbsp;:&nbsp;([0-9A-Z.]+)&nbsp;<", string:buf );
  if( fw_ver[1] ) {
    fw_version = fw_ver[1];
  } else {
    fw_ver = eregmatch( pattern:'<td noWrap align="right">[^<]+&nbsp;:&nbsp;([0-9A-Z.]+)&nbsp;</td>', string:buf );
    if( fw_ver[1] )
      fw_version = fw_ver[1];
  }

  if( fw_version != "unknown" ) {
    os_cpe    += ":" + fw_version;
    set_kb_item( name:"d-link/dir/fw_version", value:fw_version );
    if( fw_concluded )
      fw_concluded += '\n';
    fw_concluded += fw_ver[0];
    fw_conclurl  = report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  hw_ver = eregmatch( pattern:"Hardware Version.*([ABCDEINT][124]+)(</|&nbsp;)", string:buf );
  if( hw_ver[1] ) {
    hw_version = hw_ver[1];
  } else {
    hw_ver = eregmatch( pattern:'<td noWrap align="right">[^<]+&nbsp;:&nbsp;rev ([A-Z0-9]+)(</td>|&nbsp;</td>)', string:buf );
    if( hw_ver[1] )
      hw_version = hw_ver[1];
  }

  if( hw_version != "unknown" ) {
    hw_cpe    += ":" + tolower( hw_version );
    set_kb_item( name:"d-link/dir/hw_version", value:hw_version );
    hw_concluded = hw_ver[0];
    hw_conclurl  = report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( "Server: WebServer" >< banner ) {

  buf = http_get_cache( port:port, item:"/" );

  # <title>D-LINK</title>
  # <td><script>I18N("h", "Model Name");</script> : DIR-850L</td>
  # nb: Sometimes (e.g. on DIR-868L) the page gives a 200 but redirects to a new login page ("/info/Login.html")
  # Those devices are using a POST request to /HNAP1 to get the version.

  # DIR-816L:
  # <title>D-LINK SYSTEMS, INC. | Web File Access : Login</title>
  # <div class="pp">Product Page : DIR-816L<

  if( "<title>D-LINK" >< buf && ( buf =~ "Model Name.+DIR-" ||
      ( buf =~ "Product Page.+DIR-" && "Firmware Version" >< buf && "Hardware Version" >< buf ) ) ) {

    detected = TRUE;

    # DIR-850L:
    # <td><script>I18N("h", "Hardware Version");</script> : B1</td>
    # <td><script>I18N("h", "Firmware Version");</script> : 2.06</td>
    #
    # DIR-868L: (gets the version from a separate page)
    # <td><script>I18N("h", "Hardware Version");</script>:&nbsp;<label id="HWversion">--</label></td>
    # <td><script>I18N("h", "Firmware Version");</script>:&nbsp;<label id="FWversion">--</label></td>
    #
    # DIR-816L:
    # <div class="fwv">Firmware Version : 2.05<span id="fw_ver" align="left"></span></div>
    # <div class="hwv">Hardware Version : B1<span id="hw_ver" align="left"></span></div>

    mo = eregmatch( pattern:'class=(l_tb|"modelname")>DIR-([0-9A-Z]+)<', string:buf );
    if( mo[2] ) {
      model = mo[2];
    }

    if( model == "unknown" ) {
      mo = eregmatch( pattern:'"Model Name"\\);</script> : DIR-([0-9A-Z]+)<', string:buf );
      if( mo[1] )
        model = mo[1];
    }

    if( model == "unknown" ) {
      mo = eregmatch( pattern:'<div class="pp">Product Page : DIR-([0-9A-Z]+)<', string:buf );
      if( mo[1] )
        model = mo[1];
    }

    if( model != "unknown" ) {
      fw_concluded = mo[0];
      os_app += "-" + model + " Firmware";
      os_cpe += "-" + tolower( model ) + "_firmware";
      hw_app += "-" + model + " Device";
      hw_cpe += "-" + tolower( model );
      set_kb_item( name:"d-link/dir/model", value:model );
    } else {
      os_app += " Unknown Model Firmware";
      os_cpe += "-unknown_model_firmware";
      hw_app += " Unknown Model Device";
      hw_cpe += "-unknown_model";
    }

    fw_ver = eregmatch(pattern:"Firmware Version : ([0-9A-Z.]+)<", string:buf);
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
    } else {
      fw_ver = eregmatch( pattern:'"Firmware Version"\\);</script> : ([0-9.]+)</td>', string:buf );
      if( fw_ver[1] )
        fw_version = fw_ver[1];
    }

    if( fw_version != "unknown" ) {
      os_cpe    += ":" + fw_version;
      set_kb_item( name:"d-link/dir/fw_version", value:fw_version );
      if( fw_concluded )
        fw_concluded += '\n';
      fw_concluded += fw_ver[0];
      fw_conclurl  = report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    hw_ver = eregmatch( pattern:"Hardware Version.*([ABCDEIT][12])(</?|&nbsp;)", string:buf );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
    } else {
      hw_ver = eregmatch( pattern:'"Hardware Version"\\);</script> : ([^<]+)</td>', string:buf );
      if( hw_ver[1] )
        hw_version = hw_ver[1];
    }

    if( hw_version != "unknown" ) {
      hw_cpe    += ":" + tolower( hw_version );
      set_kb_item( name:"d-link/dir/hw_version", value:hw_version );
      hw_concluded = hw_ver[0];
      hw_conclurl  = report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

# Some newer Devices (e.g. DIR-868L, using the Server: WebServer banner) are now supporting / using HNAP.
if( ! detected ) {

  if( ! get_kb_item( "HNAP/" + port + "/detected" ) )
    exit( 0 );

  vendor = get_kb_item( "HNAP/" + port + "/vendor" );
  if( ! vendor || vendor != "D-Link" )
    exit( 0 );

  # e.g. DIR-868L
  hnap_model = get_kb_item( "HNAP/" + port + "/model" );
  if( ! hnap_model || hnap_model !~ "^DIR-" )
    exit( 0 );

  detected = TRUE;

  mo = eregmatch( pattern:"^DIR-(.+)", string:hnap_model );
  if( mo[1] ) {

    model = mo[1];

    hnap_mod_concl = get_kb_item( "HNAP/" + port + "/model_concluded" );
    if( hnap_mod_concl && strlen( hnap_mod_concl ) > 0 )
      fw_concluded = hnap_mod_concl;

    os_app += "-" + model + " Firmware";
    os_cpe += "-" + tolower( model ) + "_firmware";
    hw_app += "-" + model + " Device";
    hw_cpe += "-" + tolower( model );
    set_kb_item( name:"d-link/dir/model", value:model );
  } else {
    os_app += " Unknown Model Firmware";
    os_cpe += "-unknown_model_firmware";
    hw_app += " Unknown Model Device";
    hw_cpe += "-unknown_model";
  }

  # e.g. 2.03
  hnap_fw = get_kb_item( "HNAP/" + port + "/firmware" );
  fw_ver = eregmatch( pattern:"^(.+)", string:hnap_fw );
  if( fw_ver[1] ) {
    os_cpe    += ":" + fw_ver[1];
    fw_version = fw_ver[1];
    set_kb_item( name:"d-link/dir/fw_version", value:fw_version );

    hnap_fw_concl = get_kb_item( "HNAP/" + port + "/firmware_concluded" );
    if( hnap_fw_concl && strlen( hnap_fw_concl ) > 0 ) {
      if( fw_concluded )
        fw_concluded += '\n';
      fw_concluded += hnap_fw_concl;
    }
  }

  # e.g. B1
  hnap_hw = get_kb_item( "HNAP/" + port + "/hardware" );
  hw_ver = eregmatch( pattern:"^(.+)", string:hnap_hw );
  if( hw_ver[1] ) {
    hw_version = hw_ver[1];
    hw_cpe    += ":" + tolower( hw_version );
    set_kb_item( name:"d-link/dir/hw_version", value:hw_version );

    hnap_hw_concl = get_kb_item( "HNAP/" + port + "/hardware_concluded" );
    if( hnap_hw_concl && strlen( hnap_hw_concl ) > 0 ) {
      hw_concluded += hnap_hw_concl;
    }
  }

  hnap_conclurl = get_kb_item( "HNAP/" + port + "/conclurl" );
  if( hnap_conclurl && strlen( hnap_conclurl ) > 0 ) {
    fw_conclurl = hnap_conclurl;
    hw_conclurl = hnap_conclurl;
  }
}

if( detected ) {

  set_kb_item( name:"Host/is_dlink_dir_device", value:TRUE );
  set_kb_item( name:"Host/is_dlink_device", value:TRUE );

  register_and_report_os( os:os_app, cpe:os_cpe, banner_type:"D-Link DIR Device Banner / Login Page", port:port, desc:"D-Link DIR Devices Detection", runs_key:"unixoide" );
  register_product( cpe:os_cpe, location:install, port:port, service:"www" );
  register_product( cpe:hw_cpe, location:install, port:port, service:"www" );

  report = build_detection_report( app:os_app,
                                   version:fw_version,
                                   concluded:fw_concluded,
                                   concludedUrl:fw_conclurl,
                                   install:install,
                                   cpe:os_cpe );

  report += '\n\n' + build_detection_report( app:hw_app,
                                             version:hw_version,
                                             concluded:hw_concluded,
                                             concludedUrl:hw_conclurl,
                                             install:install,
                                             cpe:hw_cpe );

  log_message( port:port, data:report );
}

exit( 0 );
