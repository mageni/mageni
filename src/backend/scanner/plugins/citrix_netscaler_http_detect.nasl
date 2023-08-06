# SPDX-FileCopyrightText: 2008 nnposter
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.80024");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2008-10-24 20:15:31 +0200 (Fri, 24 Oct 2008)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Citrix NetScaler Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2008 nnposter");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Citrix NetScaler.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach url (make_list("/vpn/tmindex.html", "/vpn/index.html", "/", "/index.html", "/logon/LogonPoint/index.html", "/logon/LogonPoint/tmindex.html", "/logon/vpn/index-ext.html")) {

  res = http_get_cache(port: port, item: url);
  if (!res)
    continue;

  # <TITLE>Citrix Access Gateway - Enterprise Edition</TITLE>
  # <TITLE>Citrix Access Gateway</TITLE>
  # class="_ctxstxt_NetscalerGateway"
  # class="_ctxstxt_NetscalerAAA"
  if ((res !~ "<title>Citrix Login</title>" || res !~ 'action="(/login/do_login|/ws/login\\.pl)"') &&
      res !~ "<title>netscaler gateway</title>" &&
      res !~ "citrix access gateway(\s*-\s*.* edition)?</title>" &&
      'class="_ctxstxt_Netscaler' >!< res)
    continue;

  set_kb_item(name: "citrix/netscaler/detected", value: TRUE);
  set_kb_item(name: "citrix/netscaler/http/detected", value: TRUE);
  set_kb_item(name: "citrix/netscaler/http/port", value: port);
  set_kb_item(name: "citrix/netscaler/http/" + port + "/detectUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  version = "unknown";

  url2 = "/epa/epa.html";
  req = http_get(port: port, item: url2);
  res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);

  # var nsversion="12,0,41,23";
  vers = eregmatch(pattern: 'var nsversion="([^;]+)";', string: res);

  if (isnull(vers[1])) {
    url2 = "/api/NSConfig.wsdl";
    req = http_get(port: port, item: url2);
    res = http_keepalive_send_recv(port: port, data: req, bodyonly: FALSE);
    # <!--  #NS7.0 Build 56  -->
    vers = eregmatch(pattern: "#NS([0-9.]+ Build [[0-9]+)", string: res);
  }

  if (!isnull(vers[1])) {
    version = str_replace(string: vers[1], find: ",", replace: ".");
    version = str_replace(string: version, find: " Build ", replace: ".");
    set_kb_item(name: "citrix/netscaler/http/" + port + "/concluded", value: vers[0]);
    set_kb_item(name: "citrix/netscaler/http/" + port + "/concUrl",
                value: http_report_vuln_url(port: port, url: url2, url_only: TRUE));
  }

  set_kb_item(name: "citrix/netscaler/http/" + port + "/version", value: version);

  exit(0);
}

exit(0);
