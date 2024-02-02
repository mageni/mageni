# SPDX-FileCopyrightText: 2005 Michel Arboi
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11125");
  script_version("2023-12-15T16:10:08+0000");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MLDonkey Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 4080);
  script_mandatory_keys("MLDonkey/banner");

  script_tag(name:"summary", value:"HTTP based detection of the MLDonkey web interface.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:4080 );

banner = http_get_remote_headers( port:port );
if( ! banner )
  exit( 0 );

if( egrep( pattern:"MLDonkey", string:banner, icase:TRUE ) ) {
  if( ! egrep( pattern:"failure", string:banner, icase:TRUE ) ) {
    version = "unknown";
    url = "/";

    if( banner =~ "^HTTP/1\.[01] 40[13]" ) {
      # Server: MLdonkey/3.1.5
      vers = eregmatch( string:banner, pattern:"MLDonkey/([0-9.]+)", icase:TRUE );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        set_kb_item( name:"mldonkey/http/" + port + "/concluded", value:vers[0] );
      }
    } else if( ereg( pattern:"^HTTP/1\.[01] 200", string:banner ) ) {
      url = "/oneframe.html";
      res = http_get_cache( port:port, item:url );
      vers = eregmatch( string:res, pattern:"Welcome to MLDonkey ([0-9.]+)" );
      if( ! isnull( vers[1] ) ) {
        version = vers[1];
        set_kb_item( name:"mldonkey/http/" + port + "/concluded", value:vers[0] );
      }
    }

    set_kb_item( name:"mldonkey/detected", value:TRUE );
    set_kb_item( name:"mldonkey/http/detected", value:TRUE );
    set_kb_item( name:"mldonkey/http/port", value:port );
    set_kb_item( name:"mldonkey/http/" + port + "/concludedUrl",
                 value:http_report_vuln_url( port:port, url:url, url_only:TRUE ));

    set_kb_item( name:"mldonkey/http/" + port + "/version", value:version );
  }
}

exit(0);
