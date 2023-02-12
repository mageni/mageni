# Copyright (C) 2013 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103689");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2013-04-08 13:52:56 +0200 (Mon, 08 Apr 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("D-Link DIR Devices Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("D-LinkDIR/banner");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DIR devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8080 );
banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

detected   = FALSE;
fw_version = "unknown";
hw_version = "unknown";
model      = "unknown";
install    = "/";

# Server: Linux, WEBACCESS/1.0, DIR-850L Ver 1.10WW
# Server: Linux, HTTP/1.1, DIR-850L Ver 1.09
# Server: Linux, WEBACCESS/1.0, DIR-850L Ver 1.10
# Server: Linux, HTTP/1.1, DIR-629 Ver 1.01CN
# Server: Linux, HTTP/1.1, DIR-600 Ver 2.17
# Server: Linux, STUNNEL/1.0, DIR-850L Ver 1.15
if( _banner = egrep( string:banner, pattern:"(Server: Linux, (HTTP/1\.1|WEBACCESS/1\.0|STUNNEL/1\.0), DIR-[0-9]+[^ ]++ Ver|DIR-[0-9]+ web server)", icase:TRUE ) ) {

  detected = TRUE;
  _banner = chomp( _banner );
  fw_concluded = _banner;

  mo = eregmatch( pattern:" DIR-([0-9]+[^ ]*)", string:_banner );
  if( mo[1] )
    set_kb_item( name:"d-link/dir/http/" + port + "/model", value:mo[1] );

  fw_ver = eregmatch( pattern:"Ver ([^\r\n]+)", string:_banner );
  if( fw_ver[1] ) {
    fw_version = fw_ver[1];
    set_kb_item( name:"d-link/dir/http/" + port + "/fw_version", value:fw_version );
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
    set_kb_item( name:"d-link/dir/http/" + port + "/hw_version", value:hw_version );
    hw_concluded = hw_ver[0];
    hw_conclurl  = http_report_vuln_url( port:port, url:"/", url_only:TRUE );
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
    set_kb_item( name:"d-link/dir/http/" + port + "/model", value:model );
  }

  # DIR-615:
  # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;rev N24&nbsp;</td>
  # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;4.00&nbsp;</td>
  #
  # DIR-300:
  # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;rev A1&nbsp;</td>
  # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;1.06&nbsp;</td>
  #
  # DIR-605 with localization: (replace $localization with random name of the language)
  # <td noWrap align="right">$localizations&nbsp;:&nbsp;rev 2A1&nbsp;</td>
  # <td noWrap align="right">$localizations&nbsp;:&nbsp;2.01&nbsp;</td>
  #
  # DIR-600:
  # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;Bx&nbsp;</td>
  # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;2.05&nbsp;</td>

  fw_ver = eregmatch( pattern:">Firmware Version&nbsp;:&nbsp;([0-9A-Z.]+)&nbsp;<", string:buf );
  if( fw_ver[1] ) {
    fw_version = fw_ver[1];
  } else {
    fw_ver = eregmatch( pattern:'<td noWrap align="right">[^<]+&nbsp;:&nbsp;([0-9A-Z.]+)&nbsp;</td>', string:buf );
    if( fw_ver[1] )
      fw_version = fw_ver[1];
  }

  if( fw_version != "unknown" ) {
    set_kb_item( name:"d-link/dir/http/" + port + "/fw_version", value:fw_version );
    if( fw_concluded )
      fw_concluded += '\n    ';
    fw_concluded += fw_ver[0];
    fw_conclurl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }

  hw_ver = eregmatch( pattern:"Hardware Version.*([ABCDEINT][124x]+)(</|&nbsp;)", string:buf );
  if( hw_ver[1] ) {
    hw_version = hw_ver[1];
  } else {
    hw_ver = eregmatch( pattern:'<td noWrap align="right">[^<]+&nbsp;:&nbsp;rev ([A-Z0-9]+)(</td>|&nbsp;</td>)', string:buf );
    if( hw_ver[1] )
      hw_version = hw_ver[1];
  }

  if( hw_version != "unknown" ) {
    set_kb_item( name:"d-link/dir/http/" + port + "/hw_version", value:hw_version );
    hw_concluded = hw_ver[0];
    hw_conclurl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
  }
}

if( "Server: mini_httpd" >< banner ) {

  url = "/cgi-bin/webproc";
  buf = http_get_cache( port:port, item:url );

  if( 'target="_blank">DIR-' >< buf && "DIV_ProductPage" >< buf ) {

    detected = TRUE;

    # target="_blank">DIR-819</a>
    mo = eregmatch( pattern:'target="_blank">DIR-([0-9A-Z]+)<', string:buf );
    if( !isnull( mo[1] ) ) {
      model = mo[1];
    }

    if( model != "unknown" ) {
      fw_concluded = mo[0];
      set_kb_item( name:"d-link/dir/http/" + port + "/model", value:model );
    }

    # <span id = "DIV_FirmwareVersion">Firmware Version : </span>
    # <span class="value">1.00</span>
    fw_ver = eregmatch(pattern:"Firmware Version : </span>[^>]+>([0-9a-zA-Z.]+)<", string:buf );
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
    }

    if( fw_version != "unknown" ) {
      set_kb_item( name:"d-link/dir/http/" + port + "/fw_version", value:fw_version );
      if( fw_concluded )
        fw_concluded += '\n    ';
      fw_concluded += fw_ver[0];
      fw_conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    # <span id = "DIV_HardwareVersion">Hardware Version : </span>
    # <span class="value" style="text-transform:uppercase;">A1</span>
    hw_ver = eregmatch( pattern:"Hardware Version : </span>[^>]+>([ABCDEIT][12])<", string:buf );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
    }

    if( hw_version != "unknown" ) {
      set_kb_item( name:"d-link/dir/http/" + port + "/hw_version", value:hw_version );
      hw_concluded = hw_ver[0];
      hw_conclurl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

if( "Server: WebServer" >< banner || "Server: lighttpd" >< banner || "Server: httpd" >< banner ) {

  url = "/";
  buf = http_get_cache( port:port, item:url );

  # <title>D-LINK</title>
  # <td><script>I18N("h", "Model Name");</script> : DIR-850L</td>
  # nb: Sometimes (e.g. on DIR-868L) the page gives a 200 but redirects to a new login page ("/info/Login.html")
  # Those devices are using a POST request to /HNAP1 to get the version.

  # DIR-816L:
  # <title>D-LINK SYSTEMS, INC. | Web File Access : Login</title>
  # <div class="pp">Product Page : DIR-816L<

  # DIR-655:
  # <script>show_words(TA2)</script>: <a href="http://support.dlink.com.tw/">DIR-655</a></td>
  # <td align="right" nowrap><script>show_words(TA3)</script>: C1 &nbsp;</td>
  # <td align="right" nowrap><script>show_words(sd_FWV)</script>: 3.02</td>

  if( "<title>D-LINK" >< buf && ( buf =~ "Model Name.+DIR-" ||
      ( buf =~ "Product Page.+DIR-" && "Firmware Version" >< buf && "Hardware Version" >< buf ) ||
      ( buf =~ "show_words[(]TA2[)].+DIR-" && buf =~ "show_words[(]TA3[)]" && buf =~ "show_words[(]sd_FWV[)]" ) ||
      ( buf =~ 'class="product".+DIR-' && buf =~ 'class="hwversion"' && buf =~ 'class="version"' ) ) ) {

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
    # or:
    # <div class="fwv">Firmware Version : 2.06beta<span id="fw_ver" align="left"></span></div>
    # <div class="hwv">Hardware Version : B1<span id="hw_ver" align="left"></span></div>
    #
    # DIR-818LW:
    # <span class="version"> : 1.02</span>
    # <span class="hwversion"> : <span class="value" style="text-transform:uppercase;">A1</span>


    mo = eregmatch( pattern:'class=(l_tb|"modelname")>DIR-([0-9A-Z]+)<', string:buf );
    if( mo[2] ) {
      model = mo[2];
    }

    if( model == "unknown" ) {
      mo = eregmatch( pattern:'"Model Name"\\);</script>[ ]?: DIR-([0-9A-Z]+)<', string:buf );
      if( mo[1] )
        model = mo[1];
    }

    if( model == "unknown" ) {
      mo = eregmatch( pattern:'<div class="pp">Product Page[ ]?: DIR-([0-9A-Z]+)<', string:buf );
      if( mo[1] )
        model = mo[1];
    }

    if( model == "unknown" ) {
      mo = eregmatch( pattern:'show_words[(]TA2[)]</script>.+DIR-([0-9A-Z]+)', string:buf );
      if( mo[1] )
        model = mo[1];
    }

    if( model == "unknown" ) {
      mo = eregmatch( pattern:'class="product".+DIR-([0-9A-Z]+)', string:buf );
      if( mo[1] )
        model = mo[1];
    }

    if( model != "unknown" ) {
      fw_concluded = mo[0];
      set_kb_item( name:"d-link/dir/http/" + port + "/model", value:model );
    }

    fw_ver = eregmatch(pattern:"Firmware Version : ([0-9a-zA-Z.]+)<", string:buf);
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
    }

    if( fw_version == "unknown" ) {
      fw_ver = eregmatch( pattern:'"Firmware Version"\\);</script> : ([0-9a-zA-Z.]+)</td>', string:buf );
      if( fw_ver[1] )
        fw_version = fw_ver[1];
    }

    if( fw_version == "unknown" ) {
      fw_ver = eregmatch( pattern:'show_words\\(sd_FWV\\)</script>[A-Za-z ]*: ([0-9a-zA-Z.]+)', string:buf );
      if( fw_ver[1] )
          fw_version = fw_ver[1];
    }

    if( fw_version == "unknown" ) {
      fw_ver = eregmatch( pattern:'<span class="version">[^:]+:[^0-9A-Z]*([0-9a-zA-Z.]+)<\\/span', string:buf );
      if( fw_ver[1] )
        fw_version = fw_ver[1];
    }

    if( fw_version != "unknown" ) {
      set_kb_item( name:"d-link/dir/http/" + port + "/fw_version", value:fw_version );
      if( fw_concluded )
        fw_concluded += '\n    ';
      fw_concluded += fw_ver[0];
      fw_conclurl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    hw_ver = eregmatch( pattern:"Hardware Version.*([ABCDEIT][12])(</?|&nbsp;)", string:buf );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
    }

    if( hw_version == "unknown" ) {
      hw_ver = eregmatch( pattern:'"Hardware Version"\\);</script> : ([^<]+)</td>', string:buf );
      if( hw_ver[1] )
        hw_version = hw_ver[1];
    }

    if( hw_version == "unknown" ) {
      hw_ver = eregmatch( pattern:'show_words[(]TA3[)]</script>[A-Za-z ]*: ([0-9A-Z.]+)', string:buf );
      if( hw_ver[1] )
        hw_version = hw_ver[1];
    }

    if( hw_version == "unknown" ) {
      hw_ver = eregmatch( pattern:'<span class="hwversion">.*[:>] ?([0-9A-Z.]+)<\\/span', string:buf );
      if( hw_ver[1] )
        hw_version = hw_ver[1];
    }

    if( hw_version != "unknown" ) {
      set_kb_item( name:"d-link/dir/http/" + port + "/hw_version", value:hw_version );
      hw_concluded = hw_ver[0];
      hw_conclurl  = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

# Some devices (e.g. DIR-816) redirect to /dir_login.asp
if( banner =~ "Location:.+dir_login\.asp" ) {

  url = "/dir_login.asp";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "Ver='DIR-[0-9]+" || buf =~ 'Product Page:.+ DIR-[0-9A-Z]+' ) {

    detected = TRUE;

    mo = eregmatch( string:buf, pattern:'Product Page ?: ?DIR-([0-9A-Z]+)' );
    if( mo[1] ) {
      model = mo[1];
    }
    if( model == "unknown" ) {
      mo = eregmatch( string:buf, pattern:"Ver ?= ?'DIR-([0-9A-Z]+)'" );
      if( mo[1] )
        model = mo[1];
    }

    if( model != "unknown" ) {
      fw_concluded = mo[0];
      set_kb_item( name:"d-link/dir/http/" + port + "/model", value:model );
    }

    fw_ver = eregmatch(pattern:"Firmware Version ?: ?([0-9a-zA-Z.]+)<", string:buf);
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
    }
    if( fw_version == "unknown" ) {
      fw_ver = eregmatch( pattern:'FirmwareVer ?= ?["\']([0-9a-zA-Z.]+)["\']', string:buf );
      if( fw_ver[1] )
      fw_version = fw_ver[1];
    }

    if( fw_version != "unknown" ) {
      set_kb_item( name:"d-link/dir/http/" + port + "/fw_version", value:fw_version );
      if( fw_concluded )
        fw_concluded += '\n    ';
      fw_concluded += fw_ver[0];
      fw_conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    hw_ver = eregmatch( pattern:"Hardware Version.*([ABCDEIT][12])(</?| )", string:buf );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
    }
    if( hw_version == "unknown" ) {
      hw_ver = eregmatch( pattern:'HardwareVer ?= ?["\']([0-9A-Z]+)["\']', string:buf );
      if( hw_ver[1] )
        hw_version = hw_ver[1];
    }

    if( hw_version != "unknown" ) {
      set_kb_item( name:"d-link/dir/http/" + port + "/hw_version", value:hw_version );
      hw_concluded = hw_ver[0];
      hw_conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

if( detected ) {

  # nb: Added here to be used by active checks, that require HTTP,
  # until all D-Link detections are updated. Should be removed after
  set_kb_item( name:"Host/is_dlink_device", value:TRUE );
  # nb: The new key for D-link active checks affecting multiple device types
  set_kb_item( name:"d-link/http/detected", value:TRUE );

  set_kb_item( name:"d-link/dir/detected", value:TRUE );
  set_kb_item( name:"d-link/dir/http/detected", value:TRUE );
  set_kb_item( name:"d-link/dir/http/port", value:port );

  if( fw_concluded )
    set_kb_item( name:"d-link/dir/http/" + port + "/fw_concluded", value:fw_concluded );

  if( fw_conclurl )
    set_kb_item( name:"d-link/dir/http/" + port + "/fw_conclurl", value:fw_conclurl );

  if( hw_concluded )
    set_kb_item( name:"d-link/dir/http/" + port + "/hw_concluded", value:hw_concluded );

  if( hw_conclurl )
    set_kb_item( name:"d-link/dir/http/" + port + "/hw_conclurl", value:hw_conclurl );
}

exit( 0 );
