# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102095");
  script_version("2024-02-08T14:36:53+0000");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-01-30 09:36:18 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"executable_version");

  script_name("AnyDesk Desktop Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_anydesk_desktop_smb_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_anydesk_desktop_ssh_login_detect.nasl",
                        "gsf/gb_anydesk_udp_detect.nasl",
                        "gsf/gb_anydesk_tcp_detect.nasl");
  script_mandatory_keys("anydesk/desktop/detected");

  script_tag(name:"summary", value:"Consolidation of AnyDesk Desktop detections.");

  script_xref(name:"URL", value:"https://anydesk.com");

  exit(0);
}

if( ! get_kb_item( "anydesk/desktop/detected" ) )
  exit( 0 );

include( "host_details.inc" );

CPE = "cpe:/a:anydesk:anydesk";
version = "unknown";
location = "/";

foreach proto( make_list( "smb-login", "ssh-login" ) ) {
  version_list = get_kb_list( "anydesk/desktop/" + proto + "/*/version" );
  foreach ver( version_list ) {
    if( ver != "unknown" && version == "unknown" ) {
      version = ver;
      CPE += ":" + version;
      break;
    }
  }
}

if( ssh_port = get_kb_list( "anydesk/desktop/ssh-login/port" ) ) {
  foreach port( ssh_port ) {
    concluded = get_kb_item( "anydesk/desktop/ssh-login/" + port + "/concluded" );
    fileLocation = get_kb_item( "anydesk/desktop/ssh-login/" + port + "/location" );
    extra += '\n- SSH login on port ' + port + "/tcp";
    if( concluded )
      extra += '\n  Concluded from version/product identification result:\n' + concluded;

    if( fileLocation )
      extra += '\n  Concluded from version/product identification location:\n    ' + fileLocation;

    register_product( cpe: CPE, location: fileLocation, port: 0, service: "ssh-login" );
  }
}

if( ! isnull( concl = get_kb_item( "anydesk/desktop/smb-login/0/concluded" ) ) ) {
  fileLocation = get_kb_item( "anydesk/desktop/smb-login/0/location" );
  extra += '\n- Local Detection over SMB';
  extra += '\n  Concluded from version/product identification result:' + concl;
  extra += '\n    Location:       ' + fileLocation;

  register_product( cpe: CPE, location: fileLocation, port: 0, service: "smb-login" );
}

if( udp_port = get_kb_list( "anydesk/desktop/udp/port" ) ) {
  foreach port( udp_port ) {
    service_location = get_kb_item( "anydesk/desktop/udp/" + port + "/location" );
    extra += '\n- AnyDesk Discovery Service on port ' + port + "/udp";
    register_product( cpe: CPE, location: service_location, port: port, service: "anydesk-discovery", proto:"udp" );
  }
}

if( tcp_port = get_kb_list( "anydesk/desktop/tcp/port" ) ) {
  foreach port( tcp_port ) {
    service_location = get_kb_item( "anydesk/desktop/tcp/" + port + "/location" );
    extra += '\n- AnyDesk Service on port ' + port + "/tcp";
    register_product( cpe: CPE, location: service_location, port: port, service: "anydesk", proto:"tcp" );
  }
}

report = build_detection_report( app: "AnyDesk Desktop",
                                 version: version,
                                 install: location,
                                 cpe: CPE );
if( extra ) {
  report += '\n\nConcluded from:';
  report += extra;
}

log_message( port: 0, data: chomp( report ) );

exit( 0 );
