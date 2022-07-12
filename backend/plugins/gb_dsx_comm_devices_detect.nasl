# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.112771");
  script_version("2020-06-17T08:51:04+0000");
  script_tag(name:"last_modification", value:"2020-06-18 10:16:17 +0000 (Thu, 18 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-16 12:05:00 +0000 (Tue, 16 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("DSX Communication Devices Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of DSX communication devices.

  Note: Providing login credentials allows to extract detailed device information.");

  script_add_preference(name:"DSX User Name", value:"", type:"entry");
  script_add_preference(name:"DSX Password", value:"", type:"password");

  script_xref(name:"URL", value:"https://www.dsxinc.com/modules.htm");

  exit(0);
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

port = http_get_port( default:80 );

res = http_get_cache( port:port, item:"/" );

if( res =~ "^HTTP/1\.[01] 401" && "<strong>DSX Access Systems, Inc.</strong>" >< res ) {

  set_kb_item( name:"dsx/communication_device/detected", value:TRUE );

  hw_name = "DSX Communication Device";
  os_name = "DSX Communication Device Firmware";
  hw_cpe = "cpe:/h:dsx:communication_device";
  os_cpe = "cpe:/o:dsx:communication_device_firmware";
  version = "unknown";
  model_detected = FALSE;

  # nb: Trying to fetch the model in this early stage. Need to include the "DSX-" prefix.
  # WWW-Authenticate: Basic realm= LAN-D
  model_match = eregmatch( pattern:'WWW-Authenticate: Basic realm= ([^\n\r]+)', string:res, icase:TRUE );
  if( ! isnull( model_match[1] ) ) {
    model = "DSX-" + model_match[1];
    hw_name = "DSX " + model + " Communication Device";
    os_name = hw_name + " Firmware";
    concl = model_match[0];
    hw_cpe = "cpe:/h:dsx:" + tolower( model );
    os_cpe = "cpe:/o:dsx:" + tolower( model ) + "_firmware";
    set_kb_item( name:"dsx/model", value:model );
    model_detected = TRUE;
  }

  user = script_get_preference( "DSX User Name" );
  pass = script_get_preference( "DSX Password" );

  if( ! user && ! pass ) {
    extra = "DSX communication device detected but version unknown. Providing login credentials to this VT might allow to gather the version.";
  } else if( ! user && pass ) {
    log_message( port:port, data:"Password provided but User Name is missing." );
  } else if( user && ! pass ) {
    log_message( port:port, data:"User Name provided but Password is missing." );
  } else if( user && pass ) {
    url = "/devicedetails.ssi";
    add_headers = make_array( "Authorization", "Basic " + base64( str:user + ":" + pass ) );

    req = http_get_req( port:port, url:url, add_headers:add_headers, accept_header:"*/*" );
    res = http_keepalive_send_recv( port:port, data:req );

    if( res =~ "^HTTP/1\.[01] 200" && "DSX" >< res && "Firmware Version" >< res ) {
      # Firmware Version: DSX-LAN-D v4.14 AUG 21 2019;0;9600"
      vers = eregmatch( string:res, pattern:"Firmware Version: (DSX-[^ ]+) v([0-9.]+)" );

      #nb: If somehow the model detection from the Basic realm did not return a valuable result, we can get it post authentication.
      if( ! isnull( vers[1] ) && ! model_detected ) {
        model = vers[1];
        hw_cpe = "cpe:/h:dsx:" + tolower( model );
        os_cpe = "cpe:/o:dsx:" + tolower( model ) + "_firmware";
        set_kb_item( name:"dsx/model", value:model );
      }

      if( ! isnull( vers[2] ) ) {
        version = vers[2];
        os_cpe += ":" + version;
        concl = vers[0];
        conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );
      }
    } else {
      log_message( port:port, data:'User Name and Password provided but login failed with the following response:\n\n' + res );
    }
  }

  register_and_report_os( os:os_name, cpe:os_cpe, desc:"DSX Communication Devices Detection (HTTP)", runs_key:"unixoide" );

  report = build_detection_report( app:os_name, version:version, install:"/", cpe:os_cpe );
  report += '\n\n';
  report += build_detection_report( app:hw_name, skip_version:TRUE, install:"/", cpe:hw_cpe );

  if( concl ) {
    report += '\n\nConcluded from version/product identification result:';
    report += '\n' + concl;
    if( conclUrl ) {
      report += '\n\nConcluded from version/product identification location:';
      report += '\n' + conclUrl;
    }
  }

  if( extra ) {
    report += '\n\nExtra information:';
    report += '\n' + extra;
  }

  log_message( port:port, data:report );
}

exit( 0 );
