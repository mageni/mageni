###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arcserve_udp_detect.nasl 13679 2019-02-15 08:20:11Z cfischer $
#
# Arcserve UDP Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105294");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13679 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 09:20:11 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-06-10 17:49:06 +0200 (Wed, 10 Jun 2015)");
  script_name("Arcserve UDP Detection");

  script_tag(name:"summary", value:"The script sends a connection request to the server and attempts
  to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8014, 8015, 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

cpe = 'cpe:/a:arcserve:arcserve_unified_data_protection';

port = get_http_port( default:8014 );

host = http_host_name( port:port );
useragent = http_get_user_agent();

function check_win()
{
  data = '<?xml version="1.0" encoding="UTF-8"?>' +
         '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">' +
         '<S:Body><ns2:getVersionInfo xmlns:ns2="http://webservice.arcflash.ca.com" ' +
         'xmlns:ns3="http://data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns4="http://backup.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns5="http://restore.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns6="http://vsphere.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns7="http://browse.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns8="http://remotedeploy.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns9="http://catalog.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns10="http://activitylog.data.webservice.arcflash.ca.com/xsd"/>' +
         '</S:Body></S:Envelope>';

  len = strlen( data );

  req = 'POST /WebServiceImpl/services/FlashServiceImpl HTTP/1.1\r\n' +
        'Accept: text/xml, multipart/related\r\n' +
        'Content-Type: text/xml; charset=utf-8;\r\n' +
        'SOAPAction: "http://webservice.arcflash.ca.com/IFlashService_R16_5/getVersionInfoRequest"\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Cache-Control: no-cache\r\n' +
        'Pragma: no-cache\r\n' +
        'Host: ' + host + '\r\n' +
        'Connection: close\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "arcserve" >!< buf || "getVersionInfoResponse" >!< buf || "buildNumber" >!< buf || "majorVersion>" >!< buf  ) return;

  set_kb_item( name:"arcserve_udp/detected", value:TRUE );
  set_kb_item( name:"arcserve_udp/soap_typ", value:'windows' );
  set_kb_item( name:"arcserve_udp/soap_raw_response", value:buf );

  lines = split(buf,sep:"><", keep:FALSE);

  # Example:
  #<ns4:majorVersion>5</ns4:majorVersion>
  #<ns4:minorVersion>0</ns4:minorVersion>
  #<ns4:buildNumber>1897</ns4:buildNumber>
  #<ns4:locale>de</ns4:locale>
  #<ns4:country>DE</ns4:country>
  #<ns4:timeZoneID>Europe/Berlin</ns4:timeZoneID>
  #<ns4:timeZoneOffset>7200000</ns4:timeZoneOffset>
  #<ns4:adminName>mime</ns4:adminName>
  #<ns4:localDriverLetters>C:\</ns4:localDriverLetters>
  #<ns4:localADTPackage>-1</ns4:localADTPackage>
  #<ns4:updateNumber>3</ns4:updateNumber>
  #<ns4:productType>0</ns4:productType>
  #<ns4:dataFormat>
  #<ns4:timeFormat>HH:mm:ss</ns4:timeFormat>
  #<ns4:shortTimeFormat>HH:mm</ns4:shortTimeFormat>
  #<ns4:timeDateFormat>dd.MM.yyyy HH:mm:ss</ns4:timeDateFormat>
  #<ns4:dateFormat>dd.MM.yyyy</ns4:dateFormat/ns4:dataFormat>
  #<ns4:isDedupInstalled>false</ns4:isDedupInstalled>
  #<ns4:isWin8>false</ns4:isWin8>
  #<ns4:isReFsSupported>false</ns4:isReFsSupported>
  #<ns4:osName>Windows 7 Enterprise</ns4:osName>
  #<ns4:uefiFirmware>false</ns4:uefiFirmware>
  #<ns4:SQLServerInstalled>true</ns4:SQLServerInstalled>
  #<ns4:ExchangeInstalled>false</ns4:ExchangeInstalled>
  #<ns4:D2DInstalled>true</ns4:D2DInstalled>
  #<ns4:ARCserveBackInstalled>false</ns4:ARCserveBackInstalled>
  #<ns4:RPSInstalled>false</ns4:RPSInstalled>
  #<ns4:settingConfiged>false</ns4:settingConfiged>
  #<ns4:displayVersion>5.0</ns4:displayVersion>

  foreach line ( lines )
  {
    if( "majorVersion>" >< line )
    {
      major_version = eregmatch( pattern:'majorVersion>([^<]+)<', string:line );
      if( ! isnull( major_version[1] ) ) major = major_version[1];
    }
    else if( "minorVersion" >< line )
    {
      minor_version = eregmatch( pattern:'minorVersion>([^<]+)<', string:line );
      if( ! isnull( minor_version[1] ) ) minor = minor_version[1];
    }
    else if( "buildNumber>" >< line )
    {
      build_number = eregmatch( pattern:'buildNumber>([^<]+)<', string:line );
      if( ! isnull( build_number[1] ) )
      {
        build = build_number[1];
        set_kb_item( name:"arcserve_udp/build", value:build );
      }
    }
    else if( "updateNumber>" >< line )
    {
      update_number = eregmatch( pattern:'updateNumber>([^<]+)<', string:line );
      if( ! isnull( update_number[1] ) )
      {
        update = update_number[1];
        set_kb_item( name:"arcserve_udp/update", value:update );
      }
    }
  }

  vers = 'unknown';
  if( ! isnull( major ) ) vers = major;
  if( ! isnull( minor ) )
    vers += '.' + minor;
  else
     vers += '.0';

  if( vers != 'unknown' ) cpe += ':' + vers;

  register_product( cpe:cpe, location:'/', port:port );

  log_message( data: build_detection_report( app:"Arcserve UDP",
                                             version:vers +' (' + build +')',
                                             install:'/',
                                             cpe:cpe,
                                             concluded: version[0] ),
                port:port);

  exit( 0 );
}

function check_lin()
{
  data = '<?xml version="1.0" encoding="UTF-8"?>' +
         '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">' +
         '<S:Body><ns2:getVersionInfo xmlns:ns2="http://webservice.linuximaging.arcserve.ca.com" ' +
         'xmlns:ns3="http://backup.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns4="http://catalog.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns5="http://browse.data.webservice.arcflash.ca.com/xsd"/>' +
         '</S:Body></S:Envelope>';

  len = strlen( data );

  req = 'POST /WebServiceImpl/services/LinuximagingServiceImpl HTTP/1.1\r\n' +
        'Accept: text/xml, multipart/related\r\n' +
        'Content-Type: text/xml; charset=utf-8\r\n' +
        'SOAPAction: "http://webservice.linuximaging.arcserve.ca.com/ILinuximagingService/getVersionInfoRequest"\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Cache-Control: no-cache\r\n' +
        'Pragma: no-cache\r\n' +
        'Host: ' + host + '\r\n' +
        'Connection: close\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "arcserve" >!< buf || "getVersionInfoResponse" >!< buf || "buildNumber" >!< buf || "version>" >!< buf  ) return;

  set_kb_item( name:"arcserve_udp/detected", value:TRUE );
  set_kb_item( name:"arcserve_udp/soap_typ", value:'linux' );
  set_kb_item( name:"arcserve_udp/soap_raw_response", value:buf );

  lines = split( buf, sep:"><", keep:FALSE );

  # Example:
  # <buildNumber>3230.1</buildNumber>
  # <defaultUser>root</defaultUser>
  # <enableExcludeFile>true</enableExcludeFile>
  # <enableNonRootUser>false</enableNonRootUser>
  # <licensed>false</licensed>
  # <liveCD>false</liveCD>
  # <liveCDIsoExist>false</liveCDIsoExist>
  # <locale>en</locale>
  # <showDefaultUserWhenLogin>true</showDefaultUserWhenLogin>
  # <supportWakeOnLan>true</supportWakeOnLan>
  # <timeZoneOffset>7200000</timeZoneOffset>
  # <uiLogoutTime>10</uiLogoutTime>
  # <version>5.0</version>

  vers  = 'unknown';
  build = 'unknown';

  foreach line ( lines )
  {
    if( "version>" >< line )
    {
      version = eregmatch( pattern:"version>([^<]+)</version", string:line );
      if( ! isnull( version[1] ) )
      {
        vers = version[1];
        cpe += ':' + vers;
      }
    }
    if( "buildNumber>" >< line )
    {
      build_number = eregmatch( pattern:'buildNumber>([^<]+)</buildNumber', string:line );
      if( ! isnull( build_number[1] ) )
      {
        build = build_number[1];
        set_kb_item( name:"arcserve_udp/build", value:build );
      }
    }
  }

  register_product( cpe:cpe, location:'/', port:port );
  log_message( data: build_detection_report( app:"Arcserve UDP",
                                             version:vers +' (' + build +')',
                                             install:'/',
                                             cpe:cpe,
                                             concluded: version[0] ),
                port:port);
  exit( 0 );

}

res = http_get_cache(port: port, item: "/management/");

if (res =~ "^HTTP/1\.[01] 302" && "/samlsso?SAMLRequest=" >< res) {
  # 1st redirect to /samlsso\?SAMLRequest=...
  url = eregmatch(pattern: "(/samlsso\?SAMLRequest=.*%3D)", string: res);
  if (isnull(url[1]))
    exit(0);
  req = http_get(port: port, item: url[1]);
  res = http_keepalive_send_recv(port: port, data: req);

  # Now this is the cookie we need
  if (!cookie = http_get_cookie_from_header(buf: res, pattern: "(JSESSIONID=[^;]+)"))
    exit(0);

  # 2nd redirect to /commonauth\?sessionDataKey=...
  url = eregmatch(pattern: "(/commonauth\?sessionDataKey=.*samlsso)", string: res);
  if (isnull(url[1]))
    exit(0);

  headers = make_array("Cookie", cookie);
  req = http_get_req(port: port, url: url[1], add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  # 3rd redirect to /authenticationendpoint...
  url = eregmatch(pattern: '(/authenticationendpoint[^\r\n]+)', string: res);
  if (isnull(url[1]))
    exit(0);

  req = http_get_req(port: port, url: url[1], add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("<title>Arcserve Unified Data Protection</title>" >!< res)
    exit(0);

  version = "unknown";
  set_kb_item(name: "arcserve_udp/detected", value: TRUE);

  # <label class="login_copyright" style="margin-bottom:-5px">version 6.5.4175</label>
  vers = eregmatch(pattern: '<label class="login_copyright"[^>]+>version ([0-9.]+)<', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  # <label class="login_copyright">update 2 build 667</label>
  update = eregmatch(pattern: '<label class="login_copyright">update ([0-9]+) build ([0-9]+)<', string: res);
  if (!isnull(update[1])) {
    set_kb_item(name: "arcserve_udp/update", value: update[1]);
    extra += "Update:   " + update[1] + '\n';
  }
  if (!isnull(update[2])) {
    set_kb_item(name: "arcserve_udp/build", value: update[2]);
    extra += "Build:    " + update[2] + '\n';
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:arcserve:arcserve_unified_data_protection:");
  if (!cpe)
    cpe = 'cpe:/a:arcserve:arcserve_unified_data_protection';

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Arcserve UDP", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], extra: extra),
              port: port);
  exit(0);
}
# for older versions (5.x and below)
else {
  url = "/";
  buf = http_get_cache( item:url, port:port );

  if( "arcserve" >!< tolower( buf ) ) exit( 0 );

  check_win();
  check_lin();
}

exit(0);
