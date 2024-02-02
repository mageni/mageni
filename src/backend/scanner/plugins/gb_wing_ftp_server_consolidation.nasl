# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126623");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-13 11:27:35 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wing FTP Server Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_wing_ftp_server_ftp_detect.nasl",
                      "gb_wing_ftp_server_http_detect.nasl");
  script_mandatory_keys("wing_ftp/server/detected");

  script_tag(name:"summary", value:"Consolidation of Wing FTP Server detections.");

  script_xref(name:"URL", value:"https://www.wftpserver.com/");

  exit(0);
}

if( ! get_kb_item( "wing_ftp/server/detected" ) )
  exit( 0 );

include("host_details.inc");
include("cpe.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "ftp", "http" ) ) {

  install_list = get_kb_list( "wing_ftp/server/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port     = infos[0];
    install  = infos[1];
    version  = infos[2];
    concl    = infos[3];
    conclUrl = infos[4]; # nb: Optional and only used by the HTTP detection

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:wftpserver:wing_ftp_server:" );
    if( ! cpe )
      cpe = "cpe:/a:wftpserver:wing_ftp_server";

    if( source == "http" )
      source = "www";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';
    report += build_detection_report( app:"Wing FTP Server",
                                      version:version,
                                      install:install,
                                      cpe:cpe,
                                      concludedUrl:conclUrl,
                                      concluded:concl );
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );
