# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170552");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-23 17:18:00 +0000 (Wed, 23 Aug 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Titan FTP Server Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("titanftp/banner");

  script_tag(name:"summary", value:"HTTP based detection of Titan FTP Server.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port( default:443 );

url = "/";
concl = "";
install = "/";

res = http_get_cache( port:port, item:url );

# Server: Titan FTP Server/19.0
# Server: Titan FTP Server/16.0
if ( res =~ "Server\s*:\s*Titan FTP Server" && res =~ 'Object moved to <a href="/Logon.aspx"' ) {

  version = "unknown";

  set_kb_item( name:"titan_ftp_server/detected", value:TRUE );
  set_kb_item( name:"titan_ftp_server/http/detected", value:TRUE );
  conclUrl = http_report_vuln_url( port:port, url:url, url_only:TRUE );

  vers = eregmatch( string:res, pattern:"Server\s*:\s*Titan FTP Server/([0-9.]+)" );
  if ( ! isnull( vers[1] ) ) {
    version = vers[1];
    concl = vers[0];
  }

  set_kb_item( name:"titan_ftp_server/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concl + "#---#" + conclUrl );
}

exit( 0 );
