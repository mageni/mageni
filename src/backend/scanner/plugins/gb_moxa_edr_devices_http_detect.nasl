# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140015");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-10-25 10:43:45 +0200 (Tue, 25 Oct 2016)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa EDR Router Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Moxa EDR Router devices.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

if( ! http_can_host_asp( port:port ) )
  exit( 0 );

url = "/Login.asp";

res = http_get_cache( port:port, item:url );

if( ! res || "<TITLE>Moxa EDR</TITLE>" >!< res )
  exit( 0 );

version = "unknown";
model = "unknown";

set_kb_item( name:"moxa/edr/detected", value:TRUE );
set_kb_item( name:"moxa/edr/http/detected", value:TRUE );
set_kb_item( name:"moxa/edr/http/port", value:port );
set_kb_item( name:"moxa/edr/http/" + port + "/concludedUrl",
             value:http_report_vuln_url( port:port, url:url, url_only:TRUE ) );

if( "Industrial Secure Router" >< res || "var ProjectModel" >< res ) {
  # var ModelNmae = 'EDR-810-VPN-2GSFP-T';
  mod = eregmatch( pattern:"var Model(Nmae|Name) = '(EDR-[^']+)';", string:res );
  if( ! isnull( mod[2] ) ) {
    model = mod[2];
    set_kb_item( name:"moxa/edr/http/" + port + "/concluded", value:mod[0] );
  } else {
    if( "var ProjectModel" >< res ) {
      mn = eregmatch( pattern:'var ProjectModel = ([0-9]+);', string:res );
      if( ! isnull( mn[1] ) ) {
        type = mn[1];

        if( type == 1 )
          mod = "G903";
        else if( type == 2 )
          mod = "G902";
        else if( type == 3 )
          mod = "810";

        model = "EDR-" + mod;
        set_kb_item( name:"moxa/edr/http/" + port + "/concluded", value:mn[0] );
      }
    }
  }
} else if( "EtherDevice Secure Router" >< res ) {
  lines = split( res );
  x = 0;
  foreach line( lines ) {
    x++;
    if( "Moxa EtherDevice Secure Router" >< line ) {
      for( i = 0; i < 10; i++ ) {
        if( "EDR-" >< lines[ x + i ] ) {
          mod = eregmatch( pattern:'(EDR-[^ <]+)', string:lines[ x + i ] );
          if( ! isnull( mod[1] ) ) {
            model = mod[1];
            set_kb_item( name:"moxa/edr/http/" + port + "/concluded", value:mod[0] );
          }
        }
      }
    }
  }
}

set_kb_item( name:"moxa/edr/http/" + port + "/model", value:model );
set_kb_item( name:"moxa/edr/http/" + port + "/version", value:version );

exit( 0 );
