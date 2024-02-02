# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100419");
  script_version("2024-01-30T14:37:03+0000");
  script_tag(name:"last_modification", value:"2024-01-30 14:37:03 +0000 (Tue, 30 Jan 2024)");
  script_tag(name:"creation_date", value:"2010-01-04 18:09:12 +0100 (Mon, 04 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Barracuda Web Application Firewall Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Barracuda Web Application Firewall.");

  script_add_preference(name:"Barracuda Web Application Firewall Web UI Username", value:"", type:"entry", id:1);
  script_add_preference(name:"Barracuda Web Application Firewall Web UI Password", value:"", type:"password", id:2);

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8443);

url = "/cgi-mod/index.cgi";

res = http_get_cache(port: port, item: url);

if (egrep(pattern: "<title>Barracuda Web Application Firewall", string: res, icase: TRUE) ||
    ("<span>Barracuda</span>" >< res && "a=bws_product" >< res)) {
  version = "unknown";
  concludedUrl = '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  vers = eregmatch(string: res, pattern: "barracuda.css\?v=([0-9.]+)",icase:TRUE);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "barracuda/web_application_firewall/http/" + port + "/concluded", value: vers[0]);
  } else {
    user = script_get_preference("Barracuda Web Application Firewall Web UI Username", id: 1);
    pass = script_get_preference("Barracuda Web Application Firewall Web UI Password", id: 2);

    if (!user && !pass) {
      extra += '\n  Note: No username and/or password for web authentication were provided. This could be provided for extended version extraction.';
    } else if (!user && pass) {
      extra += '\n  Note: Password for web authentication was provided but username is missing. Please provide both.';
    } else if (user && !pass) {
      extra += '\n  Note: Username for web authentication was provided but password is missing. Please provide both.';
    } else if (user && pass) {
      url = "/restapi/v3.2/login";

      headers = make_array("Content-Type", "application/json");

      data = '{"username": "' + user + '", "password": "' + pass + '"}';

      req = http_post_put_req(port: port, url: url, data: data, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      token = eregmatch(pattern: '"token"\\s*:\\s*"([^"]+)"', string: res);
      if (!isnull(token[1])) {
        url = "/restapi/v3.2/system?groups=System&parameters=firmware-version";

        auth = base64(str: token[1] + ":" + pass);

        headers = make_array("Authorization", "Basic " + auth);

        req = http_get_req(port: port, url: url, add_headers: headers);
        res = http_keepalive_send_recv(port: port, data: req);

        # {"token":"<redacted>","data":{"System":{"firmware-version":"12.0.0.007"}},"object":"System"}
        vers = eregmatch(pattern: '"firmware-version"\\s*:\\s*"([0-9.]+)"', string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          concludedUrl += '\n    ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
          set_kb_item(name: "barracuda/web_application_firewall/http/" + port + "/concluded", value: vers[0]);
        }
      } else {
        extra += '\n  Note: Username and password were provided but authentication failed.';
      }
    }
  }

  set_kb_item(name: "barracuda/web_application_firewall/detected", value: TRUE);
  set_kb_item(name: "barracuda/web_application_firewall/http/detected", value: TRUE);
  set_kb_item(name: "barracuda/web_application_firewall/http/port", value: port);
  set_kb_item(name: "barracuda/web_application_firewall/http/" + port + "/concludedUrl", value: concludedUrl);

  set_kb_item(name: "barracuda/web_application_firewall/http/" + port + "/version", value: version);
  if (extra)
    set_kb_item(name: "barracuda/web_application_firewall/http/" + port + "/extra", value: extra);

  exit(0);
}

exit(0);
