# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170535");
  script_version("2023-08-11T16:09:05+0000");
  script_tag(name:"last_modification", value:"2023-08-11 16:09:05 +0000 (Fri, 11 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-10 07:57:28 +0000 (Thu, 10 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PKIX-SSH Detection (SSH Banner)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/pkixssh/detected");

  script_tag(name:"summary", value:"SSH banner-based detection of PKIX-SSH.");

  script_xref(name:"URL", value:"https://roumenpetrov.info/secsh/");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );

if( banner && banner =~ "SSH-.+ PKIX" ) {

  version = "unknown";
  install = port + "/tcp";

  # SSH-2.0-OpenSSH_8.0 PKIX[12.1]
  vers = eregmatch( pattern:"SSH-.+ PKIX\[([0-9.]+)\]", string:banner, icase:TRUE );
  if( vers[1] )
    version = vers[1];

  set_kb_item( name:"pkixssh/detected", value:TRUE );
  set_kb_item( name:"pkixssh/ssh/detected", value:TRUE );
  set_kb_item( name:"pkixssh/ssh/port", value:port );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:pkix_ssh_project:pkix_ssh:" );
  if( ! cpe )
    cpe = "cpe:/a:pkix_ssh_project:pkix_ssh";

  register_product( cpe:cpe, location:install, port:port, service:"ssh" );

  report = build_detection_report( app:"PKIX-SSH",
                                   version:version,
                                   install:install,
                                   cpe:cpe,
                                   concluded:banner );
  log_message( port:0, data:report );
}

exit( 0 );