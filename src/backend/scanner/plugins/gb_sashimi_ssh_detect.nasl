# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126489");
  script_version("2023-09-05T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-09-05 05:05:22 +0000 (Tue, 05 Sep 2023)");
  script_tag(name:"creation_date", value:"2023-08-16 12:20:28 +0000 (Wed, 16 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sashimi Detection (SSH Banner)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/sashimi/detected");

  script_tag(name:"summary", value:"SSH banner-based detection of Sashimi.");

  script_xref(name:"URL", value:"https://github.com/rsrdesarrollo/SaSSHimi/");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );

if( banner && banner =~ "SSH-.+sashimi" ) {

  version = "unknown";
  install = port + "/tcp";

  # SSH-2.0-sashimi-0.6.5
  vers = eregmatch( pattern:"SSH-.+sashimi-([0-9.]+)", string:banner, icase:TRUE );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"sashimi/detected", value:TRUE );
  set_kb_item( name:"sashimi/ssh/detected", value:TRUE );
  set_kb_item( name:"sashimi/ssh/port", value:port );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:sashimi:sashimi:" );
  if( ! cpe )
    cpe = "cpe:/a:sashimi:sashimi";

  register_product( cpe:cpe, location:install, port:port, service:"ssh" );

  report = build_detection_report( app:"Sashimi",
                                   version:version,
                                   install:install,
                                   cpe:cpe,
                                   concluded:banner );
  log_message( port:0, data:report );
}

exit( 0 );
