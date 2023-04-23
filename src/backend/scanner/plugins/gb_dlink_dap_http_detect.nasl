# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810234");
  script_version("2023-04-18T10:10:05+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-18 10:10:05 +0000 (Tue, 18 Apr 2023)");
  script_tag(name:"creation_date", value:"2016-12-09 15:22:03 +0530 (Fri, 09 Dec 2016)");

  script_name("D-Link DAP Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of D-Link DAP Devices.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
url = "/";
url2 = "/index.php";
url3 = "/cgi-bin/webproc";

buf = http_get_cache( item:url, port:port );
buf2 = http_get_cache( item:url2, port:port );
buf3 = http_get_cache( item:url3, port:port );

# <title>D-LINK SYSTEMS, INC. | WIRELESS REPEATER  : Login</title>
# <div class="pp"><script>show_words(TA2);</script> :  <a href="http://support.dlink.com.tw/" onclick="return jump_if();" >DAP-1320</a></div>
# <script>show_words(sd_MODE);</script>: <span id="fw_ver"> DAP-1520</span>
# <big>DAP-1522</big>
# target="_blank">DHP-W310AV</a></span>
if( ( buf =~ "Product Page ?:.*>DAP" || buf =~ 'class="pp">.*>DAP' || buf =~ 'fw_ver"> DAP-[0-9]+' || buf =~ '<a href="[^"]*http://support.dlink.com[^"]*">(DAP|DHP)-[0-9]+' ||
      buf =~ "class=l_tb>DAP-[0-9]+" || buf2 =~ "<big>DAP-[0-9]+" || buf =~ 'target="?_blank"?>(DAP|DHP)-' || buf3 =~ "target=_blank>(DAP|DHP)-" ) &&
    ( buf =~ ">Copyright.*D-Link" || buf =~ "<title>D-LINK" || buf2 =~ "<title>D-Link" ||
      buf3 =~ '"copy(w)?right.*D-Link' ) ) {

  fw_version = "unknown";
  hw_version = "unknown";
  model      = "unknown";
  install    = "/";
  hw_concluded = ""; # to make linter happy

  if( buf2 =~ "<big>DAP-[0-9]+" ) {
    buf = buf2;
    fw_conclurl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
    hw_conclurl = http_report_vuln_url( port:port, url:url2, url_only:TRUE );
  }

  # <div class="pp"><script>show_words(TA2);</script> :  <a href="http://support.dlink.com.tw/" onclick="return jump_if();" >DAP-1320</a></div>
  mo = eregmatch( pattern:"> ?((DAP|DHP)-([A-Z0-9.]+))", string:buf );
  if( isnull( mo[1] ) ) {
    # target=_blank>DAP-2020</a>
    mo = eregmatch( pattern:"target=_blank>(DAP-([0-9]+))", string:buf3 );
    fw_conclurl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
  }

  if( mo[1] ) {
    model = mo[1];
    fw_concluded = mo[0];
    set_kb_item( name:"d-link/dap/http/" + port + "/model", value:model );
  }

  # <td align="right" nowrap>Hardware Version: A1 &nbsp;&nbsp;&nbsp;Firmware Version: 1.13</td>
  fw_ver = eregmatch( pattern:'Firmware Version( |&nbsp;)?:( |&nbsp;)V?([0-9.]+)', string:buf );
  if( fw_ver[3] )
    fw_version = fw_ver[3];
  if( !fw_ver[3] ) {
    # <div class="fwv"><script>show_words(sd_FWV);</script> : <span id="fw_ver" align="left">1.00</span></div>
    fw_ver = eregmatch( pattern:'id="fw_ver" align="left">([0-9.]+)', string:buf );
    if( fw_ver[1] ) {
      fw_version = fw_ver[1];
    } else {
      # <script>show_words(_firmware);</script>: v<span id="fw_ver">1.08</span>
      fw_ver = eregmatch( pattern:'id="fw_ver">([0-9.]+)', string:buf );
      if( fw_ver[1] ) {
        fw_version = fw_ver[1];
      } else {
        # <td noWrap align="right">Firmware Version&nbsp;:&nbsp;1.21&nbsp;</td>
        fw_ver = eregmatch( pattern:'Firmware Version[^0-9]+([0-9.]+)', string:buf );
        if( fw_ver[1] ) {
          fw_version = fw_ver[1];
        } else {
          # <td id="DIV_SoftwareVersion" align="right" width="14%">:</td>
          # <td align="left" width="3%">1.00</td>
          fw_ver = eregmatch( pattern:'"DIV_SoftwareVersion"[^>]+>[^>]+>[^>]+>([0-9.]+)<', string:buf3 );
          if( fw_ver[1] ) {
            fw_version = fw_ver[1];
            fw_conclurl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
          } else {
            # nb: This was the only way to have an anchor for the regex, otherwise it could fit to any table in the response
            # eg. DAP-1360</a></td>
            # <td align="right" nowrap>[asiatic chars]: C1 &nbsp;&nbsp;&nbsp;
            # [asiatic chars]: 3.02
            fw_ver = eregmatch( pattern:"DAP-[0-9]+<\/a><\/td>\s*<td[^>]+>[^:]+:\s*[A-Z][0-9]\s*(&nbsp;)*\s*[^:]+:\s*([.0-9]+)", string:buf );
            if( fw_ver[2] ) {
              fw_version = fw_ver[2];
            } else {
              fw_ver = eregmatch( pattern:'([.0-9]+) ?<span id="fw_ver"', string:buf );
              if( fw_ver[1] )
                fw_version = fw_ver[1];
            }
          }
        }
      }
    }
  }

  if( fw_version != "unknown" ) {
    os_cpe += ":" + fw_version;
    set_kb_item( name:"d-link/dap/http/" + port + "/fw_version", value:fw_version );
    if( fw_concluded )
      fw_concluded += '\n    ';
    fw_concluded += fw_ver[0];
  }

  # <td align="right" nowrap>Hardware Version: A1 &nbsp;&nbsp;&nbsp;Firmware Version: 1.13</td>
  hw_ver = eregmatch( pattern:'>Hardware Version( |&nbsp;)?:( |&nbsp;)([0-9A-Za-z.]+)', string:buf );
  if( hw_ver[3] )
    hw_version = hw_ver[3];
  if( !hw_ver[3] ) {
    # <div class="hwv"><script>show_words(TA3);;</script> : <span id="hw_ver" align="left">A1 &nbsp;</span></div>
    hw_ver = eregmatch( pattern:'id="hw_ver" align="left">([0-9A-Za-z.]+)', string:buf );
    if( hw_ver[1] ) {
      hw_version = hw_ver[1];
    } else {
      # <script>show_words(TA3);</script>: <span id="fw_ver"> A1</span>
      hw_ver = eregmatch( pattern:'>show_words\\(TA3\\)[^=]+="fw_ver"> ([0-9A-Z]+)', string:buf );
      if( hw_ver[1] ) {
        hw_version = hw_ver[1];
      } else {
        # <td noWrap align="right">Hardware Version&nbsp;:&nbsp;rev 3A1&nbsp;</td>
        hw_ver = eregmatch( pattern:'>Hardware Version[^ ]+ ([0-9A-Z]+)', string:buf );
        if( hw_ver[1] ) {
          hw_version = hw_ver[1];
        } else {
          # <td id="DIV_HardwareVersion" align="right" width="52%">:</td>
          # <td align="left" width="3%">A1</td>
          hw_ver = eregmatch( pattern:'"DIV_HardwareVersion"[^>]+>[^>]+>[^>]+>([0-9A-Z]+)<', string:buf3 );
          if( hw_ver[1] ) {
            hw_version = hw_ver[1];
            hw_conclurl = http_report_vuln_url( port:port, url:url3, url_only:TRUE );
          } else {
            # eg. DAP-1360</a></td><td align="right" nowrap>
            hw_ver = eregmatch( pattern:"DAP-[0-9]+<\/a><\/td>\s*<td[^>]+>[^:]+:\s*([A-Z][0-9])", string:buf );
            if( hw_ver[1] ) {
              hw_version = hw_ver[1];
            } else {
              hw_ver = eregmatch( pattern:'([A-Z0-9]+) ?<span id="hw_ver"', string:buf );
              if( hw_ver[1] )
                hw_version = hw_ver[1];
            }
          }
        }
      }
    }
  }

  if( hw_version != "unknown" ) {
    set_kb_item( name:"d-link/dap/http/" + port + "/hw_version", value:hw_version );
    if( hw_concluded )
      hw_concluded += '\n    ';
    hw_concluded += hw_ver[0];
  }

  # nb: The new key for D-link active checks affecting multiple device types
  set_kb_item( name:"d-link/http/detected", value:TRUE );

  set_kb_item( name:"d-link/dap/detected", value:TRUE );
  set_kb_item( name:"d-link/dap/http/detected", value:TRUE );
  set_kb_item( name:"d-link/dap/http/port", value:port );

  if( fw_concluded && ! fw_conclurl )
    fw_conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( hw_concluded && ! hw_conclurl )
    hw_conclurl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( fw_concluded )
    set_kb_item( name:"d-link/dap/http/" + port + "/fw_concluded", value:fw_concluded );

  if( fw_conclurl )
    set_kb_item( name:"d-link/dap/http/" + port + "/fw_conclurl", value:fw_conclurl );

  if( hw_concluded )
    set_kb_item( name:"d-link/dap/http/" + port + "/hw_concluded", value:hw_concluded );

  if( hw_conclurl )
    set_kb_item( name:"d-link/dap/http/" + port + "/hw_conclurl", value:hw_conclurl );

}

exit( 0 );
