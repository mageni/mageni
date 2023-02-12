# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100681");
  script_version("2023-01-25T10:11:07+0000");
  script_tag(name:"last_modification", value:"2023-01-25 10:11:07 +0000 (Wed, 25 Jan 2023)");
  script_tag(name:"creation_date", value:"2010-06-18 12:11:06 +0200 (Fri, 18 Jun 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("TeamSpeak 2/3 Server Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service2.nasl");
  script_require_ports("Services/teamspeak-serverquery", 10011, "Services/teamspeak-tcpquery", 51234, 30033);

  script_tag(name:"summary", value:"TCP based detection of a TeamSpeak 2/3 server.");

  script_xref(name:"URL", value:"http://www.teamspeak.com/");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("dump.inc");
include("host_details.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

SCRIPT_DESC = "TeamSpeak 2/3 Server Detection (TCP)";

sport = service_get_ports( default_port_list:make_list( 10011 ), proto:"teamspeak-serverquery" ); # nb: TS3
tport = service_get_ports( default_port_list:make_list( 51234 ), proto:"teamspeak-tcpquery" ); # nb: TS2

foreach port( make_list( sport, tport ) ) {

  if( ! soc = open_sock_tcp( port ) )
    continue;

  res = recv( socket:soc, length:16 );
  if( ! res || ( "[TS]" >!< res && "TS3" >!< res ) ) {
    close( soc );
    continue;
  }

  # nb: Receive the remaining data (if any) but only for TS3. This is done because otherwise the
  # remaining data would be received in the next "recv" call below. It also helps to improve the
  # concluded reporting.
  if( "TS3" >< res ) {
    _res = recv( socket:soc, length:1024 );
    if( _res )
      res += _res;
  }

  # nb: Some clean up for the concluded reporting
  res = str_replace( string:chomp( res ), find:'\n', replace:"<newline>" );
  res = bin2string( ddata:res, noprint_replacement:"" );
  concluded = "- Initial response: " + res;

  app = "TeamSpeak Server";
  version = "unknown";
  install = port + "/tcp";
  cpe = "cpe:/a:teamspeak:teamspeak";
  extra = NULL;

  # nb: TeamSpeak 3 Server response
  if( "TS3" >< res ) {

    cmd = "version";
    send( socket:soc, data:cmd + '\n' );
    res = recv( socket:soc, length:256 );
    close( soc );

    # version=3.13.6 build=1623234157 platform=Linux
    # error id=0 msg=ok
    if( res && "version" >< res && "msg" >< res ) {

      vers = eregmatch( pattern:"version=([^ ]+) (build=([^ ]+))*", string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        res = str_replace( string:chomp( res ), find:'\n', replace:"<newline>" );
        res = bin2string( ddata:res, noprint_replacement:"" );
        concluded += '\n- Response to "' + cmd + '" command: ' + res;
      }

      if( ! isnull( vers[3] ) )
        extra = "Extracted build: " + vers[3];

      service = "teamspeak-serverquery";
      service_register( port:port, proto:service );
      app = "TeamSpeak 3 Server";
      set_kb_item( name:"teamspeak3_server/" + port, value:version );
      set_kb_item( name:"teamspeak3_server/detected", value:TRUE );
      set_kb_item( name:"teamspeak3_server/tcp/detected", value:TRUE );
      cpe += "3";

      # nb: For TS3 we're getting the running platform so register accordingly...
      # e.g.:
      # platform=Linux
      # platform=Windows
      if( "platform=" >< res ) {
        banner_type = "TeamSpeak 3 Server banner";
        # nb: "<" is used in this regex to catch the "<newline>" from above...
        platform = eregmatch( string:res, pattern:"platform=([^ <$]+)", icase:FALSE );
        if( platform[1] ) {
          if( platform[1] == "Linux" )
            os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:platform[0], desc:SCRIPT_DESC, runs_key:"unixoide" );
          else if( platform[1] == "Windows" )
            os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:platform[0], desc:SCRIPT_DESC, runs_key:"windows" );
          else
            os_register_unknown_banner( banner:platform[0], banner_type_name:banner_type, banner_type_short:"ts3_banner", port:port );
        }
      }
    }
  }

  # nb: TeamSpeak 2 (and probably prior) Server response
  else if( "[TS]" >< res ) {

    cmd = "ver";
    send( socket:soc, data:cmd + '\n' );
    res = recv( socket:soc, length:256 );
    close( soc );

    if( res ) {
      # 2.0.23.19 Linux Freeware<newline>OK
      vers = eregmatch( pattern:"([0-9.]+)", string:res );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        res = str_replace( string:chomp( res ), find:'\n', replace:"<newline>" );
        res = bin2string( ddata:res, noprint_replacement:"" );
        concluded += '\n- Response to "' + cmd + '" command: ' + res;
      }
    }

    service = "teamspeak-tcpquery";
    service_register( port:port, proto:service );
    app = "TeamSpeak 2 Server";
    set_kb_item( name:"teamspeak2_server/" + port, value:version );
    set_kb_item( name:"teamspeak2_server/detected", value:TRUE );
    set_kb_item( name:"teamspeak2_server/tcp/detected", value:TRUE );
    cpe += "2";
  }

  if( vers[1] ) {

    final_cpe = build_cpe( value:version, exp:"^([0-9.]+)(-[0-9a-zA-Z]+)?", base:cpe + ":" );
    final_cpe = str_replace( string:final_cpe, find:"-", replace:"" );
    if( ! final_cpe )
      final_cpe = cpe + ":::server";
    else
      final_cpe += "::server";
  }

  if( ! final_cpe )
    final_cpe = cpe + ":::server";

  register_product( cpe:final_cpe, location:install, port:port, service:service );

  log_message( data:build_detection_report( app:app,
                                            version:version,
                                            install:install,
                                            cpe:final_cpe,
                                            extra:extra,
                                            concluded:concluded ),
               port:port );
}

# This is the file transfer port of TS3.
# There is currently no way to identify this service
# as it won't reply even on a successful upload.
# For now just register the default 30033 (if open)
if( get_kb_item( "teamspeak3_server/detected" ) ) {

  port = 30033;
  if( ! get_port_state( port ) )
    exit( 0 );

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  service_register( port:port, proto:"teamspeak-filetransfer", message:"A TS3 file transfer service seems to be running on this port" );
  log_message( port:port, data:"A TS3 file transfer service seems to be running on this port" );
  close( soc );
}

exit( 0 );
