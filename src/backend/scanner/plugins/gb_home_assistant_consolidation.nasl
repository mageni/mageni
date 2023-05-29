# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170464");
  script_version("2023-05-18T09:08:59+0000");
  script_tag(name:"last_modification", value:"2023-05-18 09:08:59 +0000 (Thu, 18 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 16:43:11 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Home Assistant Detection Consolidation");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_home_assistant_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_home_assistant_mdns_detect.nasl",
                        "gsf/gb_home_assistant_ssh_login_detect.nasl");
  script_mandatory_keys("home_assistant/detected");

  script_tag(name:"summary", value:"Consolidation of Home Assistant detections.");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("cpe.inc");

if( ! get_kb_item( "home_assistant/detected" ) )
  exit( 0 );

report = ""; # nb: To make openvas-nasl-lint happy...
detected_version = "unknown";
install = "/";

foreach source( make_list( "http", "mdns", "ssh-login" ) ) {
  vers_list = get_kb_list( "home_assistant/" + source + "/*/version" );
  foreach vers( vers_list ) {
    if( vers != "unknown" && detected_version == "unknown" ) {
      detected_version = vers;
      set_kb_item( name: "home_assistant/version", value: detected_version );
      break;
    }
  }
}

cpe = build_cpe( value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:home-assistant:home-assistant:" );
if( ! cpe )
  cpe = "cpe:/a:home-assistant:home-assistant";

if( http_ports = get_kb_list( "home_assistant/http/port" ) ) {
  foreach port( http_ports ) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item( "home_assistant/http/" + port + "/concluded" );

    if( concluded )
      extra += '  Concluded from version/product identification result:' + concluded + '\n';

    concUrl = get_kb_item( "home_assistant/http/" + port + "/concludedUrl" );
    if( concUrl )
      extra += '  Concluded from version/product identification location:\n' + concUrl + '\n';

    extra_http = get_kb_item( "home_assistant/http/" + port + "/extra" );
    if( extra_http )
      extra += '  Extra information:\n' + extra_http + '\n';

    loc = get_kb_item( "home_assistant/http/" + port + "/location" );
    if( loc )
      install = loc;

    register_product( cpe: cpe, location: install, port: port, service: "www" );
    register_port = port;
  }
}

if( mdns_ports = get_kb_list( "home_assistant/mdns/port" ) ) {
  foreach port( mdns_ports ) {
    concluded = get_kb_item( "home_assistant/mdns/" + port + "/concluded" );
    if( concluded )
      extra += '\n' + concluded;
  }
  # nb: mDNS unually points to the HNAP port, so only register when not registered before
  if( ! register_port && port ) {
    register_port = port;
    register_product( cpe: cpe, location: install, port: register_port, service: "www" );
  }
}

if( ssh_login_ports = get_kb_list( "home_assistant/ssh-login/port" ) ) {
  foreach port( ssh_login_ports ) {
    extra += "SSH login via port " + port + '/tcp\n';

    concluded = get_kb_item( "home_assistant/ssh-login/" + port + "/concluded" );
    if( concluded )
      extra += '  Concluded from version/product identification result:\n    ' + concluded + '\n';

    register_product( cpe: cpe, location: install, port: port, service: "ssh-login" );
  }
}

os_val = get_kb_item( "home_assistant/http/" + port + "/os_name" );

if( os_val && os_val =~ "Home Assistant OS" ) {
  os_name = "Home Assistant OS";
  # nb: NVD has no dedicated CPE for the OS, used same format as for App
  os_cpe = "cpe:/o:home-assistant:home-assistant";
} else {
  os_name = "Linux/Unix";
  os_cpe = "cpe:/o:linux:kernel";
}

os_register_and_report( os: os_name, cpe: os_cpe, port: 0,
                        desc: "Home Assistant Detection Consolidation", runs_key: "unixoide" );

report = build_detection_report( app: "Home Assistant", version: detected_version, install: install, cpe: cpe );

if ( extra ) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message( port: 0, data: chomp( report ) );

exit( 0 );
