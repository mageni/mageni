# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800236");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Titan FTP Server Detection (FTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/titan_ftp_server/detected");

  script_tag(name:"summary", value:"FTP based detection of Titan FTP Server.");

  exit(0);
}

include("ftp_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

# 220 Titan FTP Server 19.00.3670 Ready.
# 220 Titan FTP Server 3.30.186 Ready.
# 220 TITAN FTP server ready.
if ( banner && banner =~ "220 Titan FTP [Ss]erver " ) {
  version = "unknown";
  install = port + "/tcp";
  concl = banner;

  ver = eregmatch( pattern:"Titan FTP [Ss]erver ([0-9.]+)", string:banner );
  if ( ! isnull( ver[1] ) )
    version = ver[1];

  set_kb_item( name:"titan_ftp_server/detected", value:TRUE );
  set_kb_item( name:"titan_ftp_server/ftp/detected", value:TRUE );
  set_kb_item( name:"titan_ftp_server/ftp/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concl );
}

exit(0);
