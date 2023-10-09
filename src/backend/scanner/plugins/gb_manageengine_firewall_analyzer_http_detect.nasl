# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811533");
  script_version("2023-08-18T16:09:48+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-18 16:09:48 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2017-07-19 13:54:26 +0530 (Wed, 19 Jul 2017)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine Firewall Analyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8060);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine Firewall Analyzer.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8060);

url = "/";
res = http_get_cache(port: port, item: url);

if (">Firewall Analyzer<" >!< res || "Firewall Analyzer" >!< res) {
  url = "/apiclient/ember/Login.jsp";
  res = http_get_cache(port: port, item: url);
  if ("Firewall Analyzer" >!< res ||
      res !~ ">Firewall Log Analytics Software from ManageEngine.*Copyright.*ZOHO Corp")
    exit(0);
}

version = "unknown";
build = "unknown";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "manageengine/products/detected", value: TRUE);
set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
set_kb_item(name: "manageengine/firewall_analyzer/detected", value: TRUE);
set_kb_item(name: "manageengine/firewall_analyzer/http/detected", value: TRUE);
set_kb_item(name: "manageengine/firewall_analyzer/http/port", value: port);

# SRC="/cachestart/125323/cacheend/apiclient/fluidicv2/javascript/jquery/jquery-3.5.1.min.js"
vers = eregmatch(pattern: "/cachestart/([0-9]+)/cacheend/", string: res);
if (!isnull(vers[1])) {
  version = substr(vers[1], 0, 1) + "." + substr(vers[1], 2, 2);
  build = vers[1];
  set_kb_item(name: "manageengine/firewall_analyzer/http/" + port + "/concluded", value: vers[0]);
}

set_kb_item(name: "manageengine/firewall_analyzer/http/" + port + "/version", value: version);
set_kb_item(name: "manageengine/firewall_analyzer/http/" + port + "/build", value: build);
set_kb_item(name: "manageengine/firewall_analyzer/http/" + port + "/concludedUrl", value: conclUrl);

exit(0);
