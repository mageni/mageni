# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105294");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-10 17:49:06 +0200 (Wed, 10 Jun 2015)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Arcserve Unified Data Protection (UDP) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8014);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Arcserve Unified Data Protection (UDP).");

  script_xref(name:"URL", value:"https://www.arcserve.com/products/arcserve-udp");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8014);

function check_win() {
  url = "/WebServiceImpl/services/FlashServiceImpl";

  headers = make_array("Content-Type", "text/xml",
                       "SOAPAction", "http://webservice.arcflash.ca.com/IFlashService_R16_5/getVersionInfoRequest");

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

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  if ("arcserve" >!< res || "getVersionInfoResponse" >!< res || "buildNumber" >!< res ||
      "majorVersion>" >!< res)
    return;

  set_kb_item(name: "arcserve/udp/detected", value: TRUE);
  set_kb_item(name: "arcserve/udp/http/detected", value: TRUE);
  set_kb_item(name: "arcserve/udp/soap_type", value: "windows");
  set_kb_item(name: "arcserve/udp/http/" + port + "/soap_raw_response", value: res);

  lines = split(res, sep: "><", keep: FALSE);

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

  foreach line (lines) {
    if ("majorVersion>" >< line) {
      major_version = eregmatch(pattern: "majorVersion>([^<]+)<", string: line);
      if (!isnull(major_version[1])) {
        major = major_version[1];
        concluded += '\n' + major_version[0];
      }
    } else if ("minorVersion" >< line) {
      minor_version = eregmatch(pattern: "minorVersion>([^<]+)<", string: line);
      if (!isnull(minor_version[1])) {
        minor = minor_version[1];
        concluded += '\n' + minor_version[0];
      }
    } else if ("buildNumber>" >< line) {
      build_number = eregmatch(pattern: "buildNumber>([^<]+)<", string: line);
      if (!isnull(build_number[1])) {
        build = build_number[1];
        set_kb_item(name: "arcserve/udp/build", value: build);
        concluded += '\n' + build_number[0];
      }
    } else if ("updateNumber>" >< line) {
      update_number = eregmatch(pattern: "updateNumber>([^<]+)<", string: line);
      if (!isnull(update_number[1])) {
        update = update_number[1];
        set_kb_item(name: "arcserve/udp/update", value: update);
        concluded += '\n' + update_number[0];
      }
    }
  }

  version = "unknown";
  install = "/";

  if (!isnull(major)) {
    version = major;
    if (!isnull(minor))
      version += "." + minor;
    else
      version += ".0";

    if (build)
      version += "." + build;
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:arcserve:arcserve_unified_data_protection:");
  if (!cpe)
    cpe = "cpe:/a:arcserve:arcserve_unified_data_protection";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Arcserve Unified Data Protection (UDP)", version: version,
                                           install: install, cpe: cpe, concluded: concluded,
                                           concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
              port: port);

  exit(0);
}

function check_lin() {
  url = "/WebServiceImpl/services/LinuximagingServiceImpl";

  headers = make_array("Content-Type", "text/xml",
                       "SOAPAction", "http://webservice.linuximaging.arcserve.ca.com/ILinuximagingService/getVersionInfoRequest");

  data = '<?xml version="1.0" encoding="UTF-8"?>' +
         '<S:Envelope xmlns:S="http://schemas.xmlsoap.org/soap/envelope/">' +
         '<S:Body><ns2:getVersionInfo xmlns:ns2="http://webservice.linuximaging.arcserve.ca.com" ' +
         'xmlns:ns3="http://backup.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns4="http://catalog.data.webservice.arcflash.ca.com/xsd" ' +
         'xmlns:ns5="http://browse.data.webservice.arcflash.ca.com/xsd"/>' +
         '</S:Body></S:Envelope>';

  req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
  req = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  if ("arcserve" >!< req || "getVersionInfoResponse" >!< req || "buildNumber" >!< req || "version>" >!< req)
    return;

  set_kb_item(name: "arcserve/udp/detected", value: TRUE);
  set_kb_item(name: "arcserve/udp/http/detected", value: TRUE);
  set_kb_item(name: "arcserve/udp/soap_type", value:"linux");
  set_kb_item(name: "arcserve/udp/http/" + port + "/soap_raw_response", value: res);

  lines = split(res, sep: "><", keep: FALSE);

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

  version = "unknown";
  install = "/";

  foreach line (lines) {
    if ("version>" >< line) {
      vers = eregmatch(pattern: "version>([^<]+)</version", string: line);
      if (!isnull(vers[1])) {
        version = vers[1];
        concluded += '\n' + vers[0];
      }
    } else if ("buildNumber>" >< line) {
      build_number = eregmatch(pattern: "buildNumber>([^<]+)<//buildNumber", string: line);
      if (!isnull(build_number[1])) {
        build = build_number[1];
        set_kb_item(name: "arcserve/udp/build", value: build);
        concluded += '\n' + build_number[0];
      }
    }
  }

  if (build)
    version += "." + build;

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:arcserve:arcserve_unified_data_protection:");
  if (!cpe)
    cpe = "cpe:/a:arcserve:arcserve_unified_data_protection";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app:"Arcserve Unified Data Protection (UDP)", version: version,
                                           install: install, cpe: cpe, concluded: concluded,
                                           concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
              port: port);
  exit(0);
}

res = http_get_cache(port: port, item: "/management/");

# Mainly installations with SSO via e.g. WSO2 Carbon Server
if (res =~ "^HTTP/1\.[01] 302" && "/samlsso?SAMLRequest=" >< res) {
  # 1st redirect to /samlsso\?SAMLRequest=...
  url = eregmatch(pattern: "(/samlsso\?SAMLRequest=.*%3D)", string: res);
  if (isnull(url[1]))
    exit(0);

  req = http_get(port: port, item: url[1]);
  res = http_keepalive_send_recv(port: port, data: req);

  # Now this is the cookie we need
  # Note: Some installations don't need/have this 2nd redirect so we can skip this
  if (cookie = http_get_cookie_from_header(buf: res, pattern: "(JSESSIONID=[^;]+)")) {

    # 2nd redirect to /commonauth\?sessionDataKey=...
    url = eregmatch(pattern: "(/commonauth\?sessionDataKey=.*samlsso)", string: res);
    if (isnull(url[1]))
      exit(0);

    headers = make_array("Cookie", cookie);
    req = http_get_req(port: port, url: url[1], add_headers: headers);
    res = http_keepalive_send_recv(port: port, data: req);
  }

  # 3rd redirect to /authenticationendpoint...
  url = eregmatch(pattern: '(/authenticationendpoint[^\r\n]+)', string: res);
  if (isnull(url[1]))
    exit(0);

  req = http_get_req(port: port, url: url[1], add_headers: headers);
  res = http_keepalive_send_recv(port: port, data: req);

  if ("<title>Arcserve Unified Data Protection</title>" >!< res)
    exit(0);

  version = "unknown";
  install = "/";
  conclUrl = http_report_vuln_url(port: port, url: url[1], url_only: TRUE);

  set_kb_item(name: "arcserve/udp/detected", value: TRUE);
  set_kb_item(name: "arcserve/udp/http/detected", value: TRUE);

  # <label class="login_copyright"> build 9.0.6034.294</label>
  vers = eregmatch(pattern: 'class="login_copyright">\\s*build\\s+([0-9.]+)', string: res);
  if (isnull(vers[1])) {
    # <label class="login_copyright" style="margin-bottom:-5px">version 6.5.4175</label>
    vers = eregmatch(pattern: '<label class="login_copyright"[^>]+>version ([0-9.]+)<', string: res);
  }

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
    cpe = "cpe:/a:arcserve:arcserve_unified_data_protection";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Arcserve Unified Data Protection (UDP)", version: version,
                                           install: install, cpe: cpe, concluded: vers[0], extra: chomp(extra),
                                           concludedUrl: conclUrl),
              port: port);
  exit(0);
}

else {
  url = "/";
  res = http_get_cache(port: port, item: url);

  if ("arcserve" >!< tolower(res) || "arcserve.js" >!< res || "Arcserve UDP" >!< res)
    exit(0);

  check_win();
  check_lin();

  # Still report if version was not extracted
  version = "unknown";
  install = "/";

  set_kb_item(name: "arcserve/udp/detected", value: TRUE);
  set_kb_item(name: "arcserve/udp/http/detected", value: TRUE);

  cpe = "cpe:/a:arcserve:arcserve_unified_data_protection";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Arcserve Unified Data Protection (UDP)", version: version,
                                           install: install, cpe: cpe,
                                           concludedUrl: http_report_vuln_url(port: port, url: url, url_only: TRUE)),
              port: port);
  exit(0);
}

exit(0);
