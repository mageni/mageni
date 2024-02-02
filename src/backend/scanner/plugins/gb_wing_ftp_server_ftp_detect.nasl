# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126558");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-12 08:55:25 +0000 (Tue, 12 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wing FTP Server Detection (FTP)");

  script_tag(name:"summary", value:"FTP based detection of Wing FTP Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/wing_ftp/server/detected");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ftp_get_port( default:21 );

if( ! banner = ftp_get_banner( port:port ) )
  exit( 0 );

detected = FALSE;

# 220 Wing FTP Server 5.0.6 ready...
# 220 Wing FTP Server ready...
# 220 Wing FTP Server ready... (Wing FTP Server Free Edition)
# 220 Wing FTP Server 7.2.8 ready...
# 220 Wing FTP Server ready... (UNREGISTERED WING FTP SERVER)
if( concl = egrep( string:banner, pattern:"220 Wing FTP Server", icase:FALSE ) ) {

  install = port + "/tcp";
  version = "unknown";
  concluded = "  " + chomp( concl );

  vers = eregmatch( string:banner, pattern:"220 Wing FTP Server ([0-9.]+)", icase:FALSE );
  if( vers )
    version = vers[1];

  set_kb_item( name:"wing_ftp/server/detected", value:TRUE );
  set_kb_item( name:"wing_ftp/server/ftp/detected", value:TRUE );
  set_kb_item( name:"wing_ftp/server/ftp/port", value:port );

  set_kb_item( name:"wing_ftp/server/ftp/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concluded );
}

exit( 0 );
