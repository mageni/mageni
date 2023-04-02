# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105591");
  script_version("2023-03-24T10:09:03+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:09:03 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-03-31 14:38:23 +0200 (Thu, 31 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Kamailio Detection (SIP)");

  script_tag(name:"summary", value:"SIP based detection of Kamailio.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("sip_detection.nasl", "sip_detection_tcp.nasl");
  script_mandatory_keys("sip/banner/available");

  exit(0);
}

include("host_details.inc");
include("sip.inc");
include("misc_func.inc");
include("port_service_func.inc");

infos = sip_get_port_proto( default_port:"5060", default_proto:"udp" );
port = infos["port"];
proto = infos["proto"];

if( ! banner = sip_get_banner( port:port, proto:proto ) )
  exit( 0 );

# Kamailio (1.4.3-notls (i386/linux))
# kamailio (5.6.4 (x86_64/linux))
if( banner !~ "kamailio" )
  exit( 0 );

vers = "unknown";
cpe = "cpe:/a:kamailio:kamailio";

set_kb_item( name:"kamailio/detected", value:TRUE );
set_kb_item( name:"kamailio/sip/detected", value:TRUE );
set_kb_item( name:"kamailio/sip/port", value:port );
set_kb_item( name:"kamailio/sip/" + port + "/proto", value:proto );
set_kb_item( name:"kamailio/sip/" + port + "/concluded", value:banner );

vers = eregmatch( pattern:"(k|K)amailio \(([^ )]+) ", string:banner );
if( ! isnull( vers[2] ) ) {
  version = vers[2];
  cpe += ":" + version;
  set_kb_item( name:"kamailio/version", value:version );
}

location = "/";

register_product( cpe:cpe, port:port, location:location, service:"sip", proto:proto );

log_message( data: build_detection_report( app:"Kamailio", version:version, install:location,
                                           cpe:cpe, concluded:banner ),
             port:port, proto:proto );
exit( 0 );
