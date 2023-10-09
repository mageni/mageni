# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:portmap:portmap";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104901");
  script_version("2023-09-13T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-09-13 05:05:22 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-09-08 10:32:24 +0000 (Fri, 08 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("RPC Portmapper Service Public WAN (Internet) / Public LAN Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_rpc_portmap_tcp_detect.nasl", "gb_rpc_portmap_udp_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("rpc/portmap/tcp_or_udp/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/EN/Themen/Unternehmen-und-Organisationen/Cyber-Sicherheitslage/Reaktion/CERT-Bund/CERT-Bund-Reports/HowTo/Offene-Portmapper-Dienste/Offene-Portmapper-Dienste.html");
  script_xref(name:"URL", value:"https://www.debian.org/doc/manuals/securing-debian-manual/rpc.en.html");
  script_xref(name:"URL", value:"https://blog.lumen.com/a-new-ddos-reflection-attack-portmapper-an-early-warning-to-the-industry/");

  script_tag(name:"summary", value:"The script checks if the target host is running a RPC Portmapper
  service accessible from a public WAN (Internet) / public LAN.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running a RPC Portmapper
  service accessible from a public WAN (Internet) / public LAN.

  Note: A configuration option 'Network type' to define if a scanned network should be seen as a
  public LAN can be found in the preferences of the following VT:

  Global variable settings (OID: 1.3.6.1.4.1.25623.1.0.12288)");

  script_tag(name:"insight", value:"A public accessible RPC Portmapper service is generally seen as
  / assumed to be a security misconfiguration.

  In addition openly accessible RPC Portmapper services can be abused for distributed denial of
  service (DDoS) reflection attacks against third parties.

  Please see the references for more information.");

  script_tag(name:"solution", value:"- Only allow access to the RPC Portmapper service from trusted
  sources

  - Disable the service if unused / not required");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("network_func.inc");
include("host_details.inc");

if( ! is_public_addr() )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE, service:"rpc-portmap" ) )
  exit( 0 );

if( ! infos = get_app_location_and_proto( port:port, cpe:CPE ) )
  exit( 0 );

proto = infos["proto"];

if( ! get_kb_item( "rpc/portmap/" + proto + "/" + port + "/detected" ) )
  exit( 99 );

security_message( port:port, proto:proto );
exit( 0 );
