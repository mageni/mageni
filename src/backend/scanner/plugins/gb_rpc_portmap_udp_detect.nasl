# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900602");
  script_version("2023-09-12T05:05:19+0000");
  script_cve_id("CVE-1999-0632");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"creation_date", value:"2009-03-12 10:50:11 +0100 (Thu, 12 Mar 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("RPC Portmapper Service Detection (UDP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Service detection");
  script_require_udp_ports(111, 121, 530, 593);

  script_xref(name:"URL", value:"https://en.wikipedia.org/wiki/Portmap");
  script_xref(name:"URL", value:"https://datatracker.ietf.org/doc/html/rfc1833");

  script_tag(name:"summary", value:"UDP based detection of a RPC portmapper service.");

  script_tag(name:"insight", value:"The RPC portmapper service is an unsecured protocol for Internet
  facing systems and should only be used on a trusted network segment, otherwise disabled. The
  software should be patched and configured properly.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("port_service_func.inc");
include("rpc.inc");
include("byte_func.inc");

RPC_PROG = 100000;
proto = "udp";
extra = "Possible known aliases / names for this product are 'port mapper', 'rpc.portmap', 'portmap' or 'rpcbind'";
# nb: Not defined in the NVD (yet). It seems there might be multiple services / vendors which
# *could* have implemented this service daemon (e.g. "rpcbind") and for now we're just using an own
# defined CPE here.
CPE = "cpe:/a:portmap:portmap";

foreach _port( make_list( 111, 121, 530, 593 ) ) {

  if( ! get_udp_port_state( _port ) )
    continue;

  if( ! rpc_get_port( program:RPC_PROG, protocol:IPPROTO_UDP, portmap:_port ) )
    continue;

  install = _port + "/" + proto;

  replace_kb_item( name:"rpc/portmap/port", value:_port );
  replace_kb_item( name:"rpc/portmap/udp/port", value:_port );
  set_kb_item( name:"rpc/portmap/detected", value:TRUE );
  set_kb_item( name:"rpc/portmap/udp/detected", value:TRUE );
  set_kb_item( name:"rpc/portmap/tcp_or_udp/detected", value:TRUE );
  set_kb_item( name:"rpc/portmap/" + proto + "/" + _port + "/detected", value:TRUE );

  service_register( port:_port, proto:"rpc-portmap", ipproto:proto );

  register_product( cpe:CPE, location:install, port:_port, service:"rpc-portmap", proto:proto );

  log_message( data:build_detection_report( app:"RPC Portmapper",
                                            skip_version:TRUE,
                                            install:install,
                                            extra:extra,
                                            cpe:CPE ),
               port:_port, proto:proto );

}

exit( 0 );
