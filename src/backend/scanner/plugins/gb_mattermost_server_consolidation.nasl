# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102065");
  script_version("2023-08-04T16:09:15+0000");
  script_tag(name:"last_modification", value:"2023-08-04 16:09:15 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-01 09:07:53 +0000 (Tue, 01 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Mattermost Server Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Mattermost Server detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_mattermost_server_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_mattermost_server_ssh_login_detect.nasl");
  script_mandatory_keys("mattermost/server/detected");

  script_xref(name:"URL", value:"https://www.mattermost.com/");

  exit(0);
}

if (!get_kb_item("mattermost/server/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

report = ""; # nb: To make openvas-nasl-lint happy...

foreach proto( make_list( "ssh-login", "http" ) ) {

  install_list = get_kb_list( "mattermost/server/" + proto + "/*/installs" );
  if( ! install_list )
    continue;

  # nb: Note that sorting the array above is currently dropping the named array index
  install_list = sort( install_list );

  foreach install( install_list ) {

    infos = split( install, sep: "#---#", keep: FALSE );
    if( max_index( infos ) < 3 )
      continue; # Something went wrong and not all required infos are there...

    port      = infos[0];
    install   = infos[1];
    version   = infos[2];
    concl     = infos[3];
    concl_url = infos[4];

    cpe = build_cpe( value: version, exp: "^([0-9.a-z]+)", base: "cpe:/a:mattermost:mattermost_server:" );
    if( ! cpe ) {
      cpe = "cpe:/a:mattermost:mattermost_server";
    }

    if( proto == "http" )
      service = "www";
    else
      service = proto;

    register_product( cpe: cpe, location: install, port: port, service: service );

    if( report )
      report += '\n\n';
    report += build_detection_report( app: "Mattermost Server",
                                      version: version,
                                      install: install,
                                      cpe: cpe,
                                      concludedUrl: concl_url,
                                      concluded: concl );
  }
}

if( report )
  log_message( port: 0, data: report );

exit(0);
