# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126600");
  script_version("2023-12-19T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-12-19 05:05:25 +0000 (Tue, 19 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-07 10:46:02 +0530 (Thu, 07 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wing FTP Server Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Wing FTP Server.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

version = "unknown";
detected = FALSE;

# Server: Wing FTP Server
# Server: Wing FTP Server(Free Edition)
# Server: Wing FTP Server(UNREGISTERED)
# Server: Wing FTP Server(<user_or_name_of_company_using_the_product>)
# Server: Wing FTP Server/3.3.5()
# Server: Wing FTP Server/3.4.5()
if( concl = egrep( string:banner, pattern:"^[Ss]erver\s*:\s*Wing FTP Server", icase:FALSE ) ) {

  detected = TRUE;

  conclUrl = "  " + http_report_vuln_url( port:port, url:"/", url_only:TRUE );
  concluded = "  " + chomp( concl );

  vers = eregmatch( string:concl, pattern:"[Ss]erver\s*:\s*Wing FTP Server/([0-9.]+)", icase:FALSE );
  if( vers )
    version = vers[1];
}

url = "/login.html";
buf = http_get_cache( item:url, port:port );

# <a href="https://www.wftpserver.com/">Wing FTP Server v7.1.8</a>
# FTP server software powered by <b><a href="https://www.wftpserver.com/">Wing FTP Server v7.2.0</a></b>
# <a href="https://www.wftpserver.com/">Wing FTP Server</a> <copyright_icon>2003-2022 <b>wftpserver.com</b> All Rights Reserved
if( concl = eregmatch( string:buf, pattern:">Wing FTP Server v([0-9.]+)", icase:FALSE ) ) {

  detected = TRUE;

  if( conclUrl )
    conclUrl += '\n';
  conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];

  if( version == "unknown" )
    version = concl[1];
}

url = "/admin_login.html";
buf = http_get_cache( item:url, port:port );

if( concl = eregmatch( string:buf, pattern:">Wing FTP Server Administrator<", icase:FALSE ) ) {

  detected = TRUE;

  if( conclUrl )
    conclUrl += '\n';
  conclUrl += "  " + http_report_vuln_url( port:port, url:url, url_only:TRUE );

  if( concluded )
    concluded += '\n';
  concluded += "  " + concl[0];
}

if( detected ) {

  install = "/";

  set_kb_item( name:"wing_ftp/server/detected", value:TRUE );
  set_kb_item( name:"wing_ftp/server/http/detected", value:TRUE );
  set_kb_item( name:"wing_ftp/server/http/port", value:port );

  set_kb_item( name:"wing_ftp/server/http/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concluded + "#---#" + conclUrl );
}

exit( 0 );
