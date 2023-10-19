# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900710");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft Internet Information Services (IIS) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  # nb: Don't add a IIS/banner script_mandatory_keys because the VT is also doing a detection based
  # on redirects.

  script_tag(name:"summary", value:"HTTP based detection of Microsoft Internet Information Services (IIS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port( default:80 );

host = http_host_name( dont_add_port:TRUE );

banner = http_get_remote_headers( port:port );
if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
  exit( 0 );

detected = FALSE;
version = "unknown";

if( concl = egrep( string:banner, pattern:"^Server\s*:\s*(Microsoft-)?IIS", icase:TRUE ) ) {
  concluded = chomp( concl );
  detected = TRUE;
  vers = eregmatch( pattern:"Server\s*:\s*(Microsoft-)?IIS/([0-9.]+)", string:concl, icase:TRUE );
  if( ! isnull( vers[2] ) )
    version = vers[2];
}

# For Proxy setups where e.g. an nginx is in front of the IIS.
if( ! detected || version == "unknown" ) {

  check_urls = make_list( "/vt-test-non-existent.html", "/vt-test/vt-test-non-existent.html" );

  # We might also be able to catch the IIS banner if we're calling an .aspx file so we're
  # adding the first found .asp/.aspx file to the list.
  asp_list = http_get_kb_file_extensions( port:port, host:host, ext:"asp*" );
  if( asp_list[0] )
    check_urls = make_list( check_urls, asp_list[0] );

  # Some found systems had also responded with a redirect, following the redirect might
  # also help to grab the banner.
  if( banner =~ "^HTTP/1\.[01] 30[0-9]" ) {
    loc = http_extract_location_from_redirect( port:port, data:banner, current_dir:"/" );
    if( loc )
      check_urls = make_list( check_urls, loc );
  }

  foreach check_url( check_urls ) {
    banner = http_get_remote_headers( port:port, file:check_url );
    if( ! banner || banner !~ "^HTTP/1\.[01] [0-9]{3}" )
      continue;

    if( concl = egrep( string:banner, pattern:"^Server\s*:\s*(Microsoft-)?IIS", icase:TRUE ) ) {
      detected = TRUE;
      vers = eregmatch( pattern:"Server\s*:\s*(Microsoft-)?IIS/([0-9.]+)", string:concl, icase:TRUE );
      if( ! isnull( vers[2] ) ) {
        if( concluded )
          concluded += '\n';
        concluded += chomp( concl );
        concl_url = http_report_vuln_url( port:port, url:check_url, url_only:TRUE );
        version = vers[2];
      }
      break;
    }
  }
}

if( detected ) {

  install = port + "/tcp";
  set_kb_item( name:"IIS/installed", value:TRUE );
  set_kb_item( name:"microsoft/iis/detected", value:TRUE );
  set_kb_item( name:"microsoft/iis/http/detected", value:TRUE );

  # nb: To tell http_can_host_asp and http_can_host_php from http_func.inc that the service support these
  replace_kb_item( name:"www/" + port + "/can_host_php", value:"yes" );
  replace_kb_item( name:"www/" + port + "/can_host_asp", value:"yes" );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:internet_information_services:" );
  if( ! cpe )
    cpe = "cpe:/a:microsoft:internet_information_services";

  register_product( cpe:cpe, location:install, port:port, service:"www" );
  log_message( data:build_detection_report( app:"Microsoft Internet Information Services (IIS)",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:concl_url,
                                            concluded:concluded ),
                                            port:port );
}

exit( 0 );
