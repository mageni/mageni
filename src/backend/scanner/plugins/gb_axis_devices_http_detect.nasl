# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.114027");
  script_version("2023-02-03T10:10:17+0000");
  script_tag(name:"last_modification", value:"2023-02-03 10:10:17 +0000 (Fri, 03 Feb 2023)");
  script_tag(name:"creation_date", value:"2018-08-29 10:46:20 +0200 (Wed, 29 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Axis Devices Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Axis devices.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );

is_axis_os = FALSE;
version = "unknown";
model = "unknown";
full_name = "unknown";
install = "/";
concluded = "";
conclUrl = "";

url = "/";
res = http_get_cache( port:port, item:url );

# AXIS M2036-LE Bullet Camera Device:
# <html><head><meta http-equiv="refresh" content="0; URL=/camera/index.html" /></head></html>
#
# AXIS Q6135-LE PTZ Network Camera:
# <meta http-equiv="refresh" content="0; URL=/aca/index.html" />
#
if ( res =~ '<meta http-equiv="refresh" content="0; URL=' ) {
  url_reg = eregmatch( pattern:'URL=([^"]+)"', string:res );

  if ( ! isnull( url_reg[1] ) ) {
    url = url_reg[1];
    res = http_get_cache( port:port, item:url );
  }
}
# Companion Eye mini L:
# <title>AXIS</title>
#
# AXIS Q6128-E PTZ Dome Network Camera:
# <title>Index page</title>
# var refreshUrl = "/view/view.shtml?id=13";
#
if ( res =~ "^HTTP/(1\.[01]|2) 200" && ( res =~ "<title>.*AXIS.*</title>" ||
    ( res =~ "<title>Index page</title>" && res =~ "/view/view.shtml" ) ) ) {

  # nb: This are older versions of AXIS OS, 6.50.x and will not be detected by the other methods
  # eg. AXIS Q8414-LVS Fixed Network Camera
  if ( res =~ "<title>Index page</title>" )
    is_axis_os = TRUE;

  # nb: For some reason P1364 cameras does not reply to any of the AXIS OS tests but this rule can be safely applied
  # Other devices have the same issue
  if ( res =~ "Axis Communications AB" && res =~ "<title>AXIS</title>" )
    is_axis_os = TRUE;

  # <TITLE>Live view / - AXIS 205 version 4.03</TITLE>
  mod = eregmatch( pattern:"AXIS ([-0-9A-Za-z. ]+) version ([0-9.]+)(</title>|</TITLE>)", string:res );
  if ( ! isnull( mod[1] ) ) {
    found = TRUE;
    model = mod[1];
    full_name = "AXIS " + model;
    concluded = "    " + mod[0];
    conclUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    if ( ! isnull( mod[2] ) ) {
      version = mod[2];
    }
  } else {
    url = "/axis-cgi/basicdeviceinfo.cgi";
    data = '{"apiVersion":"1.2","method":"getAllUnrestrictedProperties"}';

    req = http_post_put_req( port:port, url:url, data:data, add_headers:make_array( "Accept-Encoding", "gzip, deflate" ) );

    # {"apiVersion": "1.3", "data": {"propertyList": {"ProdNbr": "Q6315-LE", "HardwareID": "7C9.2", "ProdFullName": "AXIS Q6315-LE PTZ Network Camera",
    # "Version": "10.11.87", "ProdType": "PTZ Network Camera", "Brand": "AXIS", "WebURL": "http://www.axis.com", "ProdVariant": "",
    # "SerialNumber": "B8A44F5B6CEF", "ProdShortName": "AXIS Q6315-LE", "BuildDate": "Jun 16 2022 20:01"}}}
    res = http_keepalive_send_recv( port:port, data:req );

    # nb: The presence of the API is for the time being the best indicator that this is AXIS OS.
    if ( res =~ "^HTTP/(1\.[01]|2) 200" || res =~ "Unauthorized" )
      is_axis_os = TRUE;

    if ( ! res || res !~ "^HTTP/(1\.[01]|2) 200" ) {
      url = "/axis-cgi/prod_brand_info/getbrand.cgi";
      # {
      #   "Brand": {
      #    "Brand": "AXIS",
      #    "ProdType": "Network Camera",
      #    "ProdNbr": "M1125",
      #    "ProdShortName": "AXIS M1125",
      #    "ProdFullName": "AXIS M1125 Network Camera"
      #  }
      # }
      res = http_get_cache( port:port, item:url );
    }

    if ( res && res =~ "^HTTP/(1\.[01]|2) 200" && res =~ '"Brand":( )*"AXIS"' && '"ProdFullName":' >< res && '"ProdNbr":' >< res ) {
      found = TRUE;

      # nb: It seems that the CPEs used by NIST follow the pattern provided by this field. Nevertheless, it is not always present, thus the fallback.
      # "ProdShortName": "AXIS Companion Eye mini L"
      mod = eregmatch( pattern:'"ProdShortName":\\s*"([-A-Za-z0-9 ]+)"', string:res );
      if ( ! mod ) {
        # "ProdNbr": "Q6315-LE",
        # "ProdNbr": "C Eye mini L",
        mod = eregmatch( pattern:'"ProdNbr":\\s*"([-A-Za-z0-9 ]+)"', string:res );
      }

      if ( ! isnull( mod[1] ) ) {
        model = mod[1];
        concluded = "    " + mod[0];
        conclUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

        # "ProdFullName": "AXIS Q6315-LE PTZ Network Camera"
        # "ProdFullName": "AXIS Companion Eye mini L Network Camera"
        full_mod = eregmatch( pattern:'"ProdFullName":\\s*"([-A-Za-z0-9 ]+)"', string:res );

        if( ! isnull( full_mod[1] ) ) {
          full_name = full_mod[1];
          concluded += '\n    ' + full_mod[0];
        }
      }

      # nb: Last tentative to differentiate between AXIS OS and dedicated firmware
      if ( ! is_axis_os ) {
        url = "/axis-cgi/apidiscovery.cgi";
        data = '{"apiVersion":"1.0","method":"getApiList"}';

        req = http_post_put_req( port:port, url:url, data:data, add_headers:make_array( "Accept-Encoding", "gzip, deflate" ) );
        res = http_keepalive_send_recv( port:port, data:req );

        # nb: The presence of the API is for the time being the best indicator that this is AXIS OS.
        # But this is not present for all AXIS OS versions
        if ( res =~ "^HTTP/(1\.[01]|2) 200" || res =~ "Unauthorized" )
          is_axis_os = TRUE;
      }
    }
  }
}

if ( ! found ) {
  # nb: Video Server devices have both index2.shtml and view.shtml but only have the model in the index2.shtml title
  url = "/view/index2.shtml";

  res = http_get_cache( port:port, item:url );

  if ( ! res || res !~ "^HTTP/(1\.[01]|2) 200" ) {
    url = "/view/view.shtml";
    res = http_get_cache( port:port, item:url );
  }
  # <TITLE>AXIS 2400 Video Server</TITLE>
  # <title>AXIS A8004-VE Network Video Door Station</title>
  # <title>Live view  - AXIS 233D Network Dome Camera</title>
  # <title>Live view / - AXIS 205 Network Camera version 4.05</title>
  if ( res && res =~ "^HTTP/(1\.[01]|2) 200" && ( res =~ "<title>Live view.*AXIS" || res =~ "<title>AXIS" ) ) {
    mod = eregmatch( pattern:"AXIS ([-0-9A-Za-z. ]+)(</title>|</TITLE>)", string:res );
    if ( mod[1] ) {
      found = TRUE;
      model_full = mod[1];
      # <title>Live view / - AXIS 205 Network Camera version 4.05</title>
      if ( " version " >< model_full ) {
        split_mod = split( model_full, sep:" version ", keep:FALSE );
        model = split_mod[0];
        model_full = model;
        if ( split_mod[1] )
          version = split_mod[1];
      } else
        model = model_full;

      full_name = model_full;
      # nb: NVD uses CPE like cpe:/h:axis:2400_video_server or cpe:/o:axis:2100_network_camera_firmware
      if ( "Network Camera" >!< model && "Video Server" >!< model ) {
        split_mod = split( model, sep:" ", keep:FALSE );
        model = split_mod[0];
      }
      conclUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      concluded += "    " + mod[0];
    }
  }
}

if ( found ) {
  if ( ! version || version == "unknown" ) {
    url2 = "/axis-release/releaseinfo";

    req = http_get_req( port:port, url:url2, add_headers:make_array( "Accept-Encoding", "gzip, deflate" ) );
    res2 = http_keepalive_send_recv( port:port, data:req );
    #version:"1.27.24.15"
    vers = eregmatch( pattern:"version:\s*([0-9.]+)", string:res2 );
    if ( vers[1] ) {
      version = vers[1];
      conclUrl += '\n    ' + http_report_vuln_url( port:port, url:url2, url_only:TRUE );
      concluded += '\n    ' + vers[0];
    }
  }

  if ( model =~ "^AXIS " ) {
    model = substr( model, 5 );
  }

  set_kb_item( name:"axis/device/detected", value:TRUE );
  set_kb_item( name:"axis/device/axisos", value:is_axis_os );
  set_kb_item( name:"axis/device/http/detected", value:TRUE );
  set_kb_item( name:"axis/device/http/port", value:port );

  set_kb_item( name:"axis/device/http/" + port + "/model", value:model );
  set_kb_item( name:"axis/device/http/" + port + "/modelName", value:full_name );
  set_kb_item( name:"axis/device/http/" + port + "/version", value:version) ;

  if ( concluded )
      set_kb_item( name:"axis/device/http/" + port + "/concluded", value:chomp( concluded ) );

  if ( conclUrl )
    set_kb_item( name:"axis/device/http/" + port + "/concludedUrl", value:conclUrl );

  exit( 0 );
}

exit( 0 );
