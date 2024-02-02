# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170668");
  script_version("2023-11-21T05:05:52+0000");
  script_tag(name:"last_modification", value:"2023-11-21 05:05:52 +0000 (Tue, 21 Nov 2023)");
  script_tag(name:"creation_date", value:"2023-11-06 08:54:04 +0000 (Mon, 06 Nov 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tenable Nessus Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_tenable_nessus_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_tenable_nessus_smb_login_detect.nasl",
                        "gsf/gb_tenable_nessus_ssh_login_detect.nasl");
  script_mandatory_keys("tenable/nessus/detected");

  script_tag(name:"summary", value:"Consolidation of Tenable Nessus detections.");

  script_xref(name:"URL", value:"https://www.tenable.com/products/nessus");
  script_xref(name:"URL", value:"https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if( ! get_kb_item( "tenable/nessus/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...

foreach source( make_list( "http", "smb-login", "ssh-login" ) ) {

  install_list = get_kb_list( "tenable/nessus/" + source + "/*/installs" );
  if( ! install_list )
    continue;

  install_list = sort( install_list );

  foreach install( install_list ) {
    infos = split( install, sep:"#---#", keep:FALSE );
    if( max_index( infos ) < 5 )
      continue; # Something went wrong and not all required infos are there...

    port       = infos[0];
    install    = infos[1];
    name       = infos[2];
    version    = infos[3];
    ui_name    = infos[4];
    ui_vers    = infos[5];
    serv_name  = infos[6];
    serv_vers  = infos[7];
    concl      = infos[8];
    conclUrl   = infos[9];
    extra      = infos[10];

    if( source == "http" )
      source = "www";

    # nb: Switched to using the 'nessus_ui_version' field in the HTTP detection, to determine the version of Nessus,
    #     as 'server_version' does no longer corresponds to the Nessus versioning; SMB Login only extracts one version, corresponding to the Nessus product
    # eg. "nessus_ui_version":"10.6.2"
    #     "server_version":"19.7.2"
    # nb: The regex is needed as the version collected via SMB Login contains also a build number which is not included in the Nessus versioning scheme, thus we want to remove it
    # eg. SMB login : 10.6.2.20009
    #     HTTP :      10.6.2
    #     SSH login : 10.6.2
    cpe = build_cpe( value:version, exp:"^([0-9]+\.[0-9]+\.[0-9]+)", base:"cpe:/a:tenable:nessus:" );
    if( ! cpe )
      cpe = "cpe:/a:tenable:nessus";

    register_product( cpe:cpe, location:install, port:port, service:source );

    if( report )
      report += '\n\n';

    report += build_detection_report( app:name,
                                      version:version,
                                      install:install,
                                      cpe:cpe );

    # SMB Login only collects a version we use for detecting Nessus, so values would be empty for the rest
    if( ui_vers ) {
      ui_cpe = build_cpe( value:ui_vers, exp:"^([0-9.]+)", base:"cpe:/a:tenable:web_ui:" );
      if( ! ui_cpe )
        ui_cpe = "cpe:/a:tenable:web_ui";

      register_product( cpe:ui_cpe, location:install, port:port, service:source );

      report += '\n\n';
      report += build_detection_report( app:ui_name,
                                        version:ui_vers,
                                        install:install,
                                        cpe:ui_cpe );
    }

    # nb: Added Nessus Server as additional CPE because starting with Nessus version 8.12, 'server_version' field in '/server/properties' exposes a version scheme different from the one used for Nessus;
    #     this means, there is a separate component of Nessus with a distinct versioning scheme, that we can identify and register
    if( serv_vers ) {
      serv_cpe = build_cpe( value:serv_vers, exp:"^([0-9.]+)", base:"cpe:/a:tenable:nessus_server:" );
      if( ! serv_cpe )
        serv_cpe = "cpe:/a:tenable:nessus_server";

      register_product( cpe:serv_cpe, location:install, port:port, service:source );

      report += '\n\n';
      report += build_detection_report( app:serv_name,
                                        version:serv_vers,
                                        install:install,
                                        cpe:serv_cpe );
    }

    report += '\n\nConcluded from version/product identification result:\n' + concl;
    if( conclUrl )
      report += '\n\nConcluded from version/product identification location:\n' + conclUrl;
    if( extra )
      report += '\n\nExtra information:\n' + extra;
  }
}

platform_val = get_kb_item( "tenable/nessus/platform" );
if( platform_val ) {
  if( platform_val =~ "^WINDOWS" ) {
    os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:0, runs_key:"windows",
                            banner_type:"Tenable Nessus 'platform' API Response", banner:platform_val,
                            desc:"Tenable Nessus Detection Consolidation" );
  } else if( platform_val =~ "^LINUX" ) {
    os_register_and_report( os:"Linux", cpe:"cpe:/o:linux:kernel", port:0, runs_key:"unixoide",
                            banner_type:"Tenable Nessus 'platform' API Response", banner:platform_val,
                            desc:"Tenable Nessus Detection Consolidation" );
  } else {
    os_register_unknown_banner( banner:platform_val, banner_type_name:"Tenable Nessus Platform Info",
                                banner_type_short:"nessus_platform_info", port:port );
  }
}

log_message( port:0, data:chomp( report ) );

exit( 0 );
