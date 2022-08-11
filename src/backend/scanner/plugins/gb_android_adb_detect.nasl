###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_android_adb_detect.nasl 10384 2018-07-03 13:55:15Z cfischer $
#
# Android Debug Bridge (ADB) Protocol Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108447");
  script_version("$Revision: 10384 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-03 15:55:15 +0200 (Tue, 03 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-03 15:09:21 +0200 (Tue, 03 Jul 2018)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Android Debug Bridge (ADB) Protocol Detection");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("5555");

  script_tag(name:"summary", value:"The script tries to identify services supporting
  the Android Debug Bridge (ADB) Protocol.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("dump.inc");

port = 5555; # nb: Default port. Currently not possible to change this in Android
if( ! get_port_state( port ) ) exit( 0 );
if( ! service_is_unknown( port:port ) ) exit( 0 );
if( ! soc = open_sock_tcp( port ) ) exit( 0 );

# https://github.com/cstyan/adbDocumentation
# https://android.googlesource.com/platform/system/core/+/master/adb/protocol.txt
req  = "CNXN";
req += raw_string( 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x00,
                   0x07, 0x00, 0x00, 0x00, 0x32, 0x02, 0x00, 0x00,
                   0xbc, 0xb1, 0xa7, 0xb1 );
req += "host::";
req += raw_string( 0x00 );

send( socket:soc, data:req );
res = recv( socket:soc, length:512 );
close( soc );

# nb: The AUTH response has 44 bytes, the CNXN without device info 33 and with way more...
if( strlen( res ) < 33 ) exit( 0 );

hexres = hexstr( res );
strres = bin2string( ddata:res, noprint_replacement:' ' ); #nb: eregmatch isn't binary save...

# Example responses if authentication is required:
# 0x00:  41 55 54 48 01 00 00 00 00 00 00 00 14 00 00 00    AUTH............
# 0x10:  8B 09 00 00 BE AA AB B7 11 13 40 FC 53 E9 68 8F    ..........@.S.h.
# 0x20:  79 54 00 D4 DB 56 01 47 DF C6 E9 50                yT...V.G...P
# or
# 0x00:  41 55 54 48 01 00 00 00 00 00 00 00 14 00 00 00    AUTH............
# 0x10:  D0 06 00 00 BE AA AB B7 6F D0 3A 23 E9 12 65 2F    ........o.:#..e/
# 0x20:  31 7C 4F A7 3E 40 95 17 AE 1C 0C 02                1|O.>@......
authpattern  = "^415554480[1-3]0000000000000014000000";
authpattern += "....0000beaaabb7................";
authpattern += "........................$";

# Example response if no authentication is required
# and no device info is provided:
# 0x00:  43 4E 58 4E 00 00 00 01 00 10 00 00 09 00 00 00    CNXN............
# 0x10:  E4 02 00 00 BC B1 A7 B1 64 65 76 69 63 65 3A 3A    ........device::
# 0x20:  00

# Example responses if no authentication is required
# and device info is provided:
# 0x00:  43 4E 58 4E 00 00 00 01 00 10 00 00 50 00 00 00    CNXN........P...
# 0x10:  C5 1D 00 00 BC B1 A7 B1 64 65 76 69 63 65 3A 3A    ........device::
# 0x20:  72 6F 2E 70 72 6F 64 75 63 74 2E 6E 61 6D 65 3D    ro.product.name=
# 0x30:  66 75 6C 6C 5F 74 61 6E 6B 3B 72 6F 2E 70 72 6F    full_tank;ro.pro
# 0x40:  64 75 63 74 2E 6D 6F 64 65 6C 3D 41 46 54 54 3B    duct.model=AFTT;
# 0x50:  72 6F 2E 70 72 6F 64 75 63 74 2E 64 65 76 69 63    ro.product.devic
# 0x60:  65 3D 74 61 6E 6B 3B 00                            e=tank;.
# or
# 0x00:  43 4E 58 4E 00 00 00 01 00 10 00 00 69 00 00 00    CNXN........i...
# 0x10:  D7 26 00 00 BC B1 A7 B1 64 65 76 69 63 65 3A 3A    .&......device::
# 0x20:  72 6F 2E 70 72 6F 64 75 63 74 2E 6E 61 6D 65 3D    ro.product.name=
# 0x30:  74 61 69 6D 65 6E 3B 72 6F 2E 70 72 6F 64 75 63    taimen;ro.produc
# 0x40:  74 2E 6D 6F 64 65 6C 3D 50 49 58 45 4C 20 32 20    t.model=PIXEL 2 # nb: ending space
# 0x50:  58 4C 3B 72 6F 2E 70 72 6F 64 75 63 74 2E 64 65    XL;ro.product.de
# 0x60:  76 69 63 65 3D 74 61 69 6D 65 6E 3B 66 65 61 74    vice=taimen;feat
# 0x70:  75 72 65 73 3D 63 6D 64 2C 73 68 65 6C 6C 5F 76    ures=cmd,shell_v
# 0x80:  32                                                 2
cnxnpattern = "^434e584e0000000100100000..000000....0000bcb1a7b1";

# AUTH required
if( eregmatch( string:hexres, pattern:authpattern ) ) {

  found   = TRUE;
  reqauth = TRUE;
  extra   = '\nAuthentication is required.';

# No AUTH required and device info
} else if( eregmatch( string:hexres, pattern:cnxnpattern ) &&
           infos = eregmatch( string:strres, pattern:"ro\.product\.name=([^;]+);ro\.product\.model=([^;]+);ro\.product\.device=([^;]+);(features=([^\0x00]+))?" ) ) {

  found   = TRUE;
  reqauth = FALSE;
  noauth  = TRUE;

  extra   = '\nNo Authentication is required. Collected device info:\n\n';
  extra  += 'Product name:   ' + infos[1] + '\n';
  extra  += 'Product model:  ' + infos[2] + '\n';
  extra  += 'Product device: ' + infos[3];
  if( infos[5] )
    extra += '\nFeatures:       ' + infos[5];

# No AUTH required and no device info
} else if( eregmatch( string:hexres, pattern:cnxnpattern ) && strres =~ "(bootloader|device|host):.*:" ) {

  found   = TRUE;
  reqauth = FALSE;
  noauth  = TRUE;
  extra   = '\nNo Authentication is required.';
}

if( found ) {

  cpe     = "cpe:/o:google:android";
  install = port + "/tcp";
  version = "unknown";

  set_kb_item( name:"adb/" + port + "/version", value:version );
  set_kb_item( name:"adb/" + port + "/detected", value:TRUE );
  set_kb_item( name:"adb/detected", value:TRUE );

  if( noauth ) {
    set_kb_item( name:"adb/" + port + "/noauth", value:TRUE );
    set_kb_item( name:"adb/noauth", value:TRUE );
  }

  if( reqauth ) {
    set_kb_item( name:"adb/" + port + "/reqauth", value:TRUE );
    set_kb_item( name:"adb/reqauth", value:TRUE );
  }

  register_service( port:port, proto:"adb" );
  register_product( cpe:cpe, location:install, port:port );
  register_and_report_os( os:"Android", cpe:cpe, desc:"Android Debug Bridge (ADB) Protocol Detection", runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Android Debug Bridge (ADB) Protocol",
                                            version:version,
                                            install:install,
                                            extra:extra,
                                            concluded:strres,
                                            cpe:cpe ),
                                            port:port );
}

exit( 0 );