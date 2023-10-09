# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104703");
  script_version("2023-08-16T05:05:28+0000");
  script_tag(name:"last_modification", value:"2023-08-16 05:05:28 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 08:02:02 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Message Queuing (MSMQ) Detection (TCP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "nessus_detect.nasl"); # nessus_detect.nasl to avoid double check for echo tests.
  script_require_ports("Services/unknown", 1801);

  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/85498b96-f2c8-43b3-a108-c9d6269dc4af");

  script_tag(name:"summary", value:"TCP based detection of a Microsoft Message Queuing (MSMQ)
  service.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("byte_func.inc");
include("dump.inc");
include("host_details.inc");
include("port_service_func.inc");
include("msmq_func.inc");
include("os_func.inc");

port = unknownservice_get_port( default:1801 );

# nb: Set by nessus_detect.nasl if we have hit a service which echos everything back. This is done
# because the "EstablishConnection" sent and received are nearly the same. The only difference seen
# so far is the "Reserved" flag in the "BaseHeader" which seems to be "0x5A" on all tested systems
# vs. our sent "0xC0".
# But the specifications currently says the following below so we can't / shouldn't use that:
# > Reserved for future use. This field can be set to any arbitrary value when sent and MUST be
# > ignored on receipt.
if( get_kb_item( "generic_echo_test/" + port + "/failed" ) )
  exit( 0 );

# nb: Set by nessus_detect.nasl as well. We don't need to do the same test multiple times...
if( ! get_kb_item( "generic_echo_test/" + port + "/tested" ) ) {

  if( ! soc = open_sock_tcp( port ) )
    exit( 0 );

  send( socket:soc, data:"TestThis\r\n" );
  r = recv_line( socket:soc, length:10 );
  close( soc );
  # We don't want to be fooled by echo & the likes
  if( "TestThis" >< r ) {
    set_kb_item( name:"generic_echo_test/" + port + "/failed", value:TRUE );
    exit( 0 );
  }
}

debug = FALSE;
proto = "tcp";

if( ! soc = open_sock_tcp( port ) )
  exit( 0 );

con_req = msmq_create_establishconnection_pkt( debug:debug );

send( socket:soc, data:con_req );

# nb: Size of the expected packet should be always 572 bytes but we're adding "a little bit more"
# just to be on the safe side.
recv = recv( socket:soc, length:1024 );
close( soc );

if( ! recv )
  exit( 0 );

# nb:
# - See note above about the size
# - If we're sure that the expected size is 572 we could also check for exactly this size here
if( strlen( recv ) < 572 ) {
  unknown_banner_set( port:port, banner:recv, set_oid_based:TRUE );
  exit( 0 );
}

if( ! msmq_parse_establishconnection_pkt( data:recv, debug:debug ) ) {
  unknown_banner_set( port:port, banner:recv, set_oid_based:TRUE );
  exit( 0 );
}

set_kb_item( name:"msmq/service/detected", value:TRUE );
set_kb_item( name:"msmq/service/proto", value:proto );
set_kb_item( name:"msmq/service/" + proto + "/detected", value:TRUE );
set_kb_item( name:"msmq/service/" + proto + "/" + port + "/detected", value:TRUE );
set_kb_item( name:"msmq/service/" + port + "/proto", value:proto );

os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port, desc:"Microsoft Message Queuing (MSMQ) Detection (TCP)", runs_key:"windows" );

service_register( port:port, proto:"msmq", ipproto:proto );

# Store link between this VT and 2023/microsoft/gb_msmq_service_wan_access.nasl
# nb:
# - We don't use the host_details.inc functions in both so we need to call this directly
# - There is no dedicated CPE for this service available, it is just part of Windows and thus we're
#   using the Windows CPE below
register_host_detail( name:"Microsoft Message Queuing (MSMQ) Detection (TCP)", value:"cpe:/o:microsoft:windows" );
register_host_detail( name:"cpe:/o:microsoft:windows", value:port + "/" + proto );
register_host_detail( name:"port", value:port + "/" + proto );

report = "A service supporting the Microsoft Message Queuing (MSMQ) protocol is running at this port.";

log_message( port:port, data:report, proto:proto );

exit( 0 );
