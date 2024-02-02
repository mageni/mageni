# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801392");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-11-14T05:06:15+0000");
  script_tag(name:"last_modification", value:"2023-11-14 05:06:15 +0000 (Tue, 14 Nov 2023)");
  script_tag(name:"creation_date", value:"2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tenable Nessus Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8834);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Tenable Nessus.");

  script_add_preference(name:"Access key", value:"", type:"password", id:1);
  script_add_preference(name:"Secret key", value:"", type:"password", id:2);

  script_xref(name:"URL", value:"https://docs.tenable.com/vulnerability-management/Content/Settings/my-account/GenerateAPIKey.htm");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:8834 );

# nb: Detection of Nessus 5.x and below
url = "/feed";
res = http_get_cache( item:url, port:port );

if( "<web_server_version>" >< res || "<server_version>" >< res || "<nessus_type>" >< res ) {

  conclUrl  = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  install   = port + "/tcp";
  version   = "unknown";
  versionWs = "unknown";
  type      = "unknown";
  feed      = "unknown";
  versionUi = "unknown";

  nessusWsVersion = eregmatch( pattern:"<web_server_version>([0-9.]+)", string:res );
  nessusVersion   = eregmatch( pattern:"<server_version>([0-9.]+)", string:res );
  nessusType      = eregmatch( pattern:"<nessus_type>([a-zA-Z ()]+)", string:res );
  nessusFeed      = eregmatch( pattern:"<feed>([a-zA-Z ]+)", string:res );
  nessusUiVersion = eregmatch( pattern:"<nessus_ui_version>([0-9.]+)", string:res );

  if( nessusVersion[1] )   version = nessusVersion[1];
  if( nessusWsVersion[1] ) versionWs = nessusWsVersion[1];
  if( nessusType[1] )      type = nessusType[1];
  if( nessusFeed[1] )      feed = nessusFeed[1];
  if( nessusUiVersion[1] ) versionUi = nessusUiVersion[1];

  set_kb_item( name:"tenable/nessus/detected", value:TRUE );
  set_kb_item( name:"tenable/nessus/http/detected", value:TRUE );
  set_kb_item( name:"tenable/nessus/http/port", value:port );
  set_kb_item( name:"tenable/nessus/http/" + port + "/web_server/version", value:versionWs );
  set_kb_item( name:"tenable/nessus/http/" + port + "/version", value:version );
  set_kb_item( name:"tenable/nessus/http/" + port + "/web_ui/version", value:versionUi );

  concl = "  " + nessusVersion[0] + '\n' + nessusWsVersion[0] + '\n' + nessusFeed[0] + '\n' + nessusType[0] + '\n' + nessusUiVersion[0];
  extra = '  Nessus Web Server version is: "' + versionWs + '"\n' + 'Nessus type is: "' + type + '"\n' + 'Nessus feed is: "' + feed + '"';

  set_kb_item( name:"tenable/nessus/http/" + port + "/installs", value:port + "#---#" + install + "#---#Tenable Nessus#---#" + version + "#---#Tenable Nessus Web UI#---#" +
               versionUi + "#---#Tenable Nessus Web Server#---#" + versionWs + "#---#" + concl + "#---#" + conclUrl + "#---#" + extra );

  exit( 0 );
}

# nb: Detection of Nessus 6.x+
url = "/server/properties";
res = http_get_cache( item:url, port:port );

# {"nessus_type":"Nessus Home","server_version":"7.0.0","nessus_ui_build":"106","nessus_ui_version":"7.0.0","server_build":"M20106"}
if( res =~ "^HTTP/1\.[01] 200" && egrep( string:res, pattern:'^\\{".*(nessus_type|nessus_ui_version|nessus_ui_build)":"', icase:TRUE ) ) {

  conclUrl      = "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  install       = port + "/tcp";
  version       = "unknown";
  build         = "unknown";
  serverVersion = "unknown";
  serverBuild   = "unknown";
  uiVersion     = "unknown";
  uiBuild       = "unknown";
  type          = "unknown";

  nessusUiVersion = eregmatch( pattern:'nessus_ui_version":"([^",]+)[",]', string:res );
  # nb: Only around 30% of targets expose version information unauthenticated, but all reply are successful, code 200
  if( isnull( nessusUiVersion ) ) {
    acc_key = script_get_preference( "Access key", id:1 );
    secret_key = script_get_preference( "Secret key", id:2 );
    if( ! acc_key || ! secret_key ) {
      extra = "  Tenable Nessus and '/server/properties' API detected which does not expose version to unauthenticated requests. Providing an 'Access key' and a 'Secret key' (see referenced URL) to the preferences of the VT 'Tenable Nessus Detection (HTTP)' (OID: 1.3.6.1.4.1.25623.1.0.801392) might allow to gather the version from the API.";
    } else {
      key_content = "accessKey=" + acc_key + "; secretKey=" + secret_key + ";";
      add_headers = make_array( "X-ApiKeys", key_content );
      req = http_get_req( port:port, url:url, add_headers:add_headers );
      res = http_keepalive_send_recv( port:port, data:req );

      if( res && ( '"server_version":"' >!< res ) ) {
        extra = "  'Access key' and 'Secret key' provided but retrieving version failed with the following response:" + '\n\n' + res;
      } else if( ! res ) {
        extra = "  'Access key' and 'Secret key' provided but login to the API failed without a response from the target.";
      }
      nessusUiVersion = eregmatch( pattern:'nessus_ui_version":"([^",]+)[",]', string:res );
    }
  }

  nessusType          = eregmatch( pattern:'nessus_type":"([^",]+)[",]', string:res );
  nessusServerVersion = eregmatch( pattern:'server_version":"([^",]+)[",]', string:res );
  nessusServerBuild   = eregmatch( pattern:'server_build":"([^",]+)[",]', string:res );
  nessusUiBuild       = eregmatch( pattern:'nessus_ui_build":"([^",]+)[",]', string:res );
  platform_val        = eregmatch( pattern:'platform":"([^",]+)[",]', string:res );

  if( nessusType[1] ) {
    type      = nessusType[1];
    app       = "Tenable " + nessusType[1];
    uiApp     = "Tenable " + nessusType[1] + " Web UI";
    serverApp = "Tenable " + nessusType[1] + " Server";
    concl     = "  " + nessusType[0];
  } else {
    app       = "Tenable Nessus";
    uiApp     = "Tenable Nessus Web UI";
    serverApp = "Tenable Nessus Server";
  }

  # nb: Starting with version 8.12, server_version and nessus_ui_version are no longer equal and only nessus_ui_version reflect Nessus versioning scheme
  if( ! isnull( nessusUiVersion[1] ) ) {
    uiVersion = nessusUiVersion[1];
    version   = nessusUiVersion[1];
    if( concl )
      concl += '\n';
    concl += "  " + nessusUiVersion[0];
  }

  if( ! isnull( nessusUiBuild[1] ) ) {
    uiBuild = nessusUiBuild[1];
    build   = nessusUiBuild[1];
    if( concl )
      concl += '\n';
    concl += "  " + nessusUiBuild[0];
  }

  if( ! isnull( nessusServerVersion[1] ) ) {
    serverVersion = nessusServerVersion[1];
    if( concl )
      concl += '\n';
    concl += "  " + nessusServerVersion[0];
  }

  if( nessusServerBuild[1] ) {
    serverBuild = nessusServerBuild[1];
    if( concl )
      concl += '\n';
    concl += "  " + nessusServerBuild[0];
  }

  set_kb_item( name:"tenable/nessus/detected", value:TRUE );
  set_kb_item( name:"tenable/nessus/http/detected", value:TRUE );
  set_kb_item( name:"tenable/nessus/http/port", value:port );
  set_kb_item( name:"tenable/nessus/http/" + port + "/version", value:uiVersion );
  set_kb_item( name:"tenable/nessus/http/" + port + "/build", value:uiBuild );
  set_kb_item( name:"tenable/nessus/http/" + port + "/server/version", value:serverVersion );
  set_kb_item( name:"tenable/nessus/http/" + port + "/server/build", value:serverBuild );
  set_kb_item( name:"tenable/nessus/http/" + port + "/web_ui/version", value:uiVersion );
  set_kb_item( name:"tenable/nessus/http/" + port + "/web_ui/build", value:uiBuild );
  set_kb_item( name:"tenable/nessus/http/" + port + "/type", value:type );

  if( platform_val[1] ) {
    if( concl )
      concl += '\n';
    concl += "  " + platform_val[0];
    set_kb_item( name:"tenable/nessus/platform", value:platform_val[1] );
  }

  set_kb_item( name:"tenable/nessus/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + app +"#---#" + uiVersion + "#---#" + uiApp +
               "#---#" + uiVersion + "#---#" + serverApp + "#---#" + serverVersion  + "#---#" + concl + "#---#" + conclUrl + "#---#" + extra );

  exit( 0 );
}

# nb: Just as a last fallback if all other detection methods are failing.
banner = http_get_remote_headers( port:port );
if( concl = egrep( pattern:"^[Ss]erver\s*:\s*NessusWWW", string:banner, icase:FALSE ) ) {
  concl   = "  " + concl;
  version = "unknown";
  install = port + "/tcp";

  set_kb_item( name:"tenable/nessus/detected", value:TRUE );
  set_kb_item( name:"tenable/nessus/http/detected", value:TRUE );
  set_kb_item( name:"tenable/nessus/http/port", value:port );
  set_kb_item( name:"tenable/nessus/http/" + port + "/version", value:version );
  set_kb_item( name:"tenable/nessus/http/" + port + "/server/version", value:version );
  set_kb_item( name:"tenable/nessus/http/" + port + "/web_ui/version", value:version );

  set_kb_item( name:"tenable/nessus/http/" + port + "/installs", value:port + "#---#" + install + "#---#Tenable Nessus#---#" + version + "#---#Tenable Nessus Web UI#---#" +
               version + "#---#Tenable Nessus Server#---#" + version + "#---#" + concl );
}

exit( 0 );
