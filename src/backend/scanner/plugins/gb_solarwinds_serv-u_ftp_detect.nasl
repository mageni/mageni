# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801117");
  script_version("2023-04-20T09:44:42+0000");
  script_tag(name:"last_modification", value:"2023-04-20 09:44:42 +0000 (Thu, 20 Apr 2023)");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SolarWinds Serv-U Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_mandatory_keys("ftp/serv-u/detected");

  script_tag(name:"summary", value:"FTP based detection of SolarWinds Serv-U.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port( default:21 );
banner = ftp_get_banner( port:port );

# 220 Serv-U FTP Server v15.0 ready...
# 200 Name=Serv-U; Version=15.0.0.0; OS=Windows Server 2012; OSVer=6.2.9200; CaseSensitive=0;
# 220 Serv-U FTP Server v6.2 for WinSock ready...
#
if( ! banner || ! concl = egrep( string:banner, pattern:"Serv-U", icase:FALSE ) )
  exit( 0 );

set_kb_item( name:"solarwinds/servu/ftp/" + port + "/concluded", value:chomp( concl ) );

# Response to CSID command (See ftp_get_banner() in ftp_func.inc)
vers = eregmatch( string:banner, pattern:"Name=Serv-U; Version=([^;]+);" );
if( ! isnull( vers[1] ) ) {
  set_kb_item( name:"solarwinds/servu/ftp/" + port + "/version", value:vers[1] );
} else {
  vers = eregmatch( pattern:"Serv-U FTP Server v([0-9.]+)", string:banner );
  if( ! isnull( vers[1] ) )
    set_kb_item( name:"solarwinds/servu/ftp/" + port + "/version", value:vers[1] );
}

set_kb_item( name:"solarwinds/servu/detected", value:TRUE );
set_kb_item( name:"solarwinds/servu/ftp/detected", value:TRUE );
set_kb_item( name:"solarwinds/servu/ftp/port", value:port );

exit( 0 );
