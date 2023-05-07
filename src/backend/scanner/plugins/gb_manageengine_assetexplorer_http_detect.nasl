# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805189");
  script_version("2023-04-25T10:19:16+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-25 10:19:16 +0000 (Tue, 25 Apr 2023)");
  script_tag(name:"creation_date", value:"2015-05-22 15:22:45 +0530 (Fri, 22 May 2015)");
  script_name("ZOHO ManageEngine AssetExplorer Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ZOHO ManageEngine AssetExplorer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:8080 );

res = http_get_cache( item:"/",  port:port );

if( ">ManageEngine AssetExplorer<" >< res ) {

  version   = "unknown";
  build     = "unknown";
  location  = "/";
  concluded = '    URL:     ' + http_report_vuln_url( port:port, url:location, url_only:TRUE );

  vers = eregmatch( pattern:"version&nbsp;([0-9.]+)<", string:res );
  if( isnull( vers[1] ) )
    vers = eregmatch( pattern:"ManageEngine AssetExplorer &nbsp;([0-9.]+)<", string:res );
  if( isnull( vers[1] ) )
    vers = eregmatch( string:res, pattern:"ManageEngine AssetExplorer','https?://.*','([0-9.]+)'", icase:TRUE );
  if( ! isnull( vers[1] ) ) {
    version = vers[1];
    concluded += '\n    Version: ' + vers[0];
  }

  buildnumber = eregmatch( pattern:"build=([0-9.]+)", string:res );
  if( isnull( buildnumber[1] ) ) {
    # eg. /scripts/ClientLogger.js?6125
    buildnumber = eregmatch( pattern: "\.js\?([0-9]+)", string:res );
  }

  if( ! isnull( buildnumber[1] ) ) {
    build = buildnumber[1];
    concluded += '\n    Build:   ' + buildnumber[0];
  }

  set_kb_item( name:"manageengine/products/http/detected", value:TRUE );
  set_kb_item( name:"manageengine/assetexplorer/detected", value:TRUE );
  set_kb_item( name:"manageengine/assetexplorer/http/detected", value:TRUE );
  set_kb_item( name:"manageengine/assetexplorer/http/port", value:port );
  set_kb_item( name:"manageengine/assetexplorer/http/" + port + "/detected", value:TRUE );
  set_kb_item( name:"manageengine/assetexplorer/http/" + port + "/location", value:location );
  set_kb_item( name:"manageengine/assetexplorer/http/" + port + "/concluded", value:concluded );
  set_kb_item( name:"manageengine/assetexplorer/http/" + port + "/version", value:version );
  set_kb_item( name:"manageengine/assetexplorer/http/" + port + "/build", value:build );

  exit( 0 );
}

exit( 0 );
