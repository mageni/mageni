# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112353");
  script_version("2023-10-06T16:09:51+0000");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"creation_date", value:"2018-08-08 13:38:12 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Buffalo NAS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 9000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Buffalo LinkStation / TeraStation
  Network Attached Storage devices.");

  script_xref(name:"URL", value:"https://www.buffalotech.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");

fingerprint = "b810a5f2a0528eafd7d23e25380aa03d";

port = http_get_port( default:9000 );

model = "unknown";
version = "unknown";
concluded = "";
series = "";

foreach dir( make_list( "/", "/ui" ) ) {

  curr_dir = dir;
  if( dir == "/" )
    dir = "";

  url = dir + "/";
  res = http_get_cache( item:url, port:port );

  logo_req = http_get( port:port, item:dir + "/images/logo.png" );
  logo_res = http_keepalive_send_recv( port:port, data:logo_req, bodyonly:TRUE );

  if( ! isnull( logo_res ) )
    md5 = hexstr( MD5( logo_res ) );

  if( "<title>WebAccess</title>" >< res && 'xtheme-buffalo.css">' >< res && fingerprint == md5 ) {
    found = TRUE;
    concUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    break;
  }

  if( ! found ) {
    concl = eregmatch( pattern:"<title>(TeraStation|LinkStation)", string:res );
    if( ! isnull(concl[1]) ) {
      found = TRUE;
      concluded += '\n    ' + concl[0];
      series = concl[1];
      concUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }

  # nb: Handle is below, no need to check each dir
  if( "<title>BUFFALO</title>" >< res )
    break;
}

base_url = "/";
base_res = http_get_cache( item:base_url, port:port );

if( ! found ) {
  if( "/WebAccess.htm" >< base_res ) {
    url = "/WebAccess.htm";
    res = http_get_cache( item:url, port:port );

    if( "<title>WebAccess</title>" >< res && 'xtheme-buffalo.css">' >< res ) {
      found = TRUE;
      concUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }
  }
}

if( ! found ) {
  url = base_url;
  res = base_res;
  # HTTP/1.1 302 Found
  # Location: /?id=14599
  if ( ( base_res =~ "^HTTP/1\.[01] 302" ) && ( loc = http_extract_location_from_redirect( port:port, data:base_res, current_dir:curr_dir ) ) ) {
    url = loc;
    res = http_get_cache( item:url, port:port );
  }

  if( "<title>BUFFALO</title>" >< res ) {
    concUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    url = "/nasapi/";

    timestamp = gettimeofday();
    tpid_components = split( timestamp, sep:".", keep:FALSE );
    tpid = tpid_components[0] + substr( tpid_components[1], 0, 2 );

    data = '{"jsonrpc":"2.0","method":"get_portal_info","params":{},"id":"' + tpid + '"}';

    header = make_array( "Accept-Encoding", "gzip, deflate",
                         "X-Requested-With", "XMLHttpRequest",
                         "Content-Type", "application/json" );
    # nb: We send the POST first as there are devices that reply to GET requests also, but with bogus data
    req = http_post_put_req( port:port, url:url, data:data, add_headers:header );
    buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

    if( buf && ( concl = eregmatch( pattern:'"series_name"\\s*:\\s*"(TeraStation|LinkStation)"', string:buf ) ) ) {
      found = TRUE;
      series = concl[1];
      concluded += '\n    ' + concl[0];
      concUrl += '\n    ' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      # "product_name": "TS5410D"
      # "product_name": "LS220D"
      mod = eregmatch( pattern:'"product_name"\\s*:\\s*"([^"]+)"', string:buf );

      if( ! isnull( mod[1] ) ) {
        model = mod[1];
        concluded += '\n    ' + mod[0];
      }
      # "fw_version_major": "1.70"
      # "fw_version_major": ""
      fw_vers_maj = eregmatch( pattern:'"fw_version_major"\\s*:\\s*"([.0-9]+)"', string:buf );

      if( ! isnull( fw_vers_maj[1] ) ) {
        version = fw_vers_maj[1];
        concluded += '\n    ' + fw_vers_maj[0];

        # "fw_version_minor": ""
        # "fw_version_minor": "0.01"
        fw_vers_min = eregmatch( pattern:'"fw_version_minor"\\s*:\\s*"([.0-9]+)"', string:buf );

        if( ! isnull( fw_vers_min[1] ) ) {
          version += "-" + fw_vers_min[1];
          concluded += '\n    ' + fw_vers_min[0];
        }
      }
    }
  }
}

if( ! found ) {
  url = "/cgi-bin/top.cgi";
  res = http_get_cache( item:url, port:port );
  if( res && res =~ "^HTTP/1\.[01] 200" && ( 'value="View LinkStation manual"' >< res || "<title>LinkStation" >< res ||
                                             'value="View TeraStation manual"' >< res || "<title>TeraStation" >< res ) ) {
    found = TRUE;

    concUrl = "    " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
    # <title>LinkStation - LS-QL  (MICRODATA)</title>
    # <title>TeraStation PRO - TS-HTGL/R5
    mod = eregmatch( pattern:"<title>(LinkStation|TeraStation( PRO)?) - ([^ ()]+)", string:res );
    if ( ! isnull( mod[3] ) ) {
      concluded += '\n    ' + mod[0];
      model = mod[3];
      series = mod[1];
    }

    if( ! series ) {
      if( 'value="View LinkStation manual"' >< res || "<title>LinkStation" >< res ) {
        series = "LinkStation";
      } else {
        series = "TeraStation";
      }
    }
  }
}

if( found ) {
  location = "/";

  set_kb_item( name:"buffalo/linkstation_or_terastation/detected", value:TRUE );
  set_kb_item( name:"buffalo/nas/detected", value:TRUE );
  set_kb_item( name:"buffalo/nas/http/detected", value:TRUE );
  set_kb_item( name:"buffalo/nas/http/port", value:port );

  cpe_model = tolower( model );
  if( "/" >< cpe_model )
    cpe_model = str_replace( string:cpe_model, find:"/", replace:"%2f" );

  if( model != "unknown" ) {
    os_app = "Buffalo NAS " + series + " " + model + " Firmware";
    os_cpe = "cpe:/o:buffalo:" + cpe_model + "_firmware";
    hw_app = "Buffalo NAS " + series + " " + model + " Device";
    hw_cpe = "cpe:/h:buffalo:" + cpe_model;
  } else {
    tmp_model = "Unknown Model";
    if( series )
      tmp_model = series + " " + tmp_model;
    cpe_tmp_model = str_replace( string:tmp_model, find:" ", replace:"_" );
    cpe_tmp_model = tolower( cpe_tmp_model );

    os_app = "Buffalo NAS " + tmp_model + " Firmware";
    os_cpe = "cpe:/o:buffalo:" + cpe_tmp_model + "_firmware";
    hw_app = "Buffalo NAS "+ tmp_model + " Device";
    hw_cpe = "cpe:/h:buffalo:" + cpe_tmp_model;
  }

  if( version != "unknown" )
    os_cpe += ":" + version;

  register_product( cpe:hw_cpe, location:location, port:port, service:"www" );
  register_product( cpe:os_cpe, location:location, port:port, service:"www" );

  os_register_and_report( os:os_app, cpe:os_cpe, port:port,
                        desc:"Buffalo NAS HTTP Detection", runs_key:"unixoide" );

  report  = build_detection_report( app:os_app,
                                    version:version,
                                    install:location,
                                    cpe:os_cpe );
  report += '\n\n';
  report += build_detection_report( app:hw_app,
                                    skip_version:TRUE,
                                    install:location,
                                    cpe:hw_cpe );

  detection_methods += '\n\nHTTP(s) on port ' + port + "/tcp";

  if( concluded && concUrl )
    detection_methods += '\n  Concluded:' + concluded + '\n  from URL(s):\n' + concUrl;
  else if( concUrl )
    detection_methods += '\n  Concluded from URL(s):\n' + concUrl;

  report += '\n\nDetection methods:' + detection_methods;

  log_message( port:port, data:chomp( report ) );
}

exit(0);
