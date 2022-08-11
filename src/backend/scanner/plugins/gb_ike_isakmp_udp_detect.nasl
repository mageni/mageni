# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117461");
  script_version("2021-06-29T06:22:51+0000");
  script_tag(name:"last_modification", value:"2021-06-29 10:13:44 +0000 (Tue, 29 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-05-28 11:07:40 +0000 (Fri, 28 May 2021)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IKE / ISAKMP Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("gb_open_udp_ports.nasl", "echo_udp.nasl");
  script_require_udp_ports("Services/udp/unknown", 500, 4500); # nb: 4500/udp is NAT-T IKE (RFC 3947 NAT-Traversal encapsulation)

  script_tag(name:"summary", value:"UDP based detection of services supporting the Internet Key
  Exchange (IKE) Protocol / Internet Security Association and Key Management Protocol (ISAKMP).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("port_service_func.inc");
include("ike_isakmp_func.inc");
include("host_details.inc");
include("misc_func.inc");
include("byte_func.inc");
include("list_array_func.inc");

ports = unknownservice_get_ports( default_port_list:make_list( 500, 4500 ), ipproto:"udp" );

foreach port( ports ) {

  # nb: As the service detection below depends on the service responding with our initiator SPI
  # this should make sure that we're not doing any false reporting against UDP echo services.
  if( get_kb_item( "echo_udp/" + port + "/detected" ) )
    continue;

  # nb: See comment in isakmp_create_transforms_packet_from_list()
  foreach used_list( make_list( "short_transforms_list", "full_fransforms_list" ) ) {

    if( used_list == "full_fransforms_list" ) {
      # nb: Need to wait a few seconds as some tested services didn't respond on subsequent
      # requests in a short amount of time.
      sleep( 10 );
    }

    # nb: Many IKE services only accepting requests if originating from the following source ports:
    # Standard IKE: 500/udp
    # NAT-T IKE: 4500/udp
    if( port == 4500 )
      sport = port;
    else
      sport = 500;

    if( ! soc = open_priv_sock_udp( dport:port, sport:sport ) )
      continue;

    if( used_list == "short_transforms_list" )
      use_short_transforms_list = TRUE;
    else
      use_short_transforms_list = FALSE;

    transforms_info = isakmp_create_transforms_packet_from_list( enable_short_list:use_short_transforms_list );
    if( ! transforms_info ) {
      close( soc );
      continue;
    }

    transforms = transforms_info[0];
    transforms_num = transforms_info[1];
    my_initiator_spi = rand_str( length:8, charset:"abcdefghiklmnopqrstuvwxyz0123456789" );

    req = isakmp_create_request_packet( port:port, ipproto:"udp", exchange_type:"Identity Protection (Main Mode)", transforms:transforms, transforms_num:transforms_num, initiator_spi:my_initiator_spi );
    # nb: To send an aggressive mode packet:
    # req = isakmp_create_request_packet( port:port, ipproto:"udp", exchange_type:"Aggressive", transforms:transforms, transforms_num:transforms_num, initiator_spi:my_initiator_spi, dhgroup:1, aggressive_mode_id:"vpngroup" );
    if( ! req ) {
      close( soc );
      continue;
    }

    send( socket:soc, data:req );
    buf = recv( socket:soc, length:1024 );
    close( soc );

    # nb: Full IKE/ISAKMP header (v1 and v2) should be at least 28 bytes (if no Payload is returned by
    # the remote service like a "Notification" one.
    if( ! buf || strlen( buf ) < 28 )
      continue;

    res_initiator_spi = substr( buf, 0, 7 );
    # nb: Shouldn't be empty but still checking just to be sure...
    if( ! res_initiator_spi )
      continue;

    if( res_initiator_spi != my_initiator_spi )
      continue;

    # Includes the major (e.g. 1) and the minor version (e.g. 2).
    ike_vers = buf[ 17 ];
    # nb: Shouldn't be empty / FALSE / NULL but still checking just to be sure...
    if( ! ike_vers )
      continue;

    # nb: From ike_isakmp_func.inc. Currently supported: 1.0 and 2.0. This is just used as an
    # confirmation / service verification in addition to the SPI one above.
    ike_vers_text = VERSIONS[ike_vers];
    if( ! ike_vers_text )
      continue;

    if( used_list == "full_fransforms_list" )
      set_kb_item( name:"isakmp/udp/" + port + "/full_transforms_list_required", value:TRUE );

    set_kb_item( name:"ike/detected", value:TRUE );
    set_kb_item( name:"ike/udp/detected", value:TRUE );

    service_register( port:port, ipproto:"udp", proto:"isakmp" );

    log_message( port:port, proto:"udp", data:"A service supporting the IKE/ISAKMP protocol is running at this port." );

    break; # Stop if the initial "full_list" based request was successful.
  }
}

exit( 0 );