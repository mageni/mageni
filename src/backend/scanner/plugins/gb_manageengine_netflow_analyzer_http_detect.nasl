# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140778");
  script_version("2023-08-18T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-08-18 05:05:27 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-02-15 17:20:38 +0700 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine NetFlow Analyzer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8060);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine NetFlow Analyzer.");

  script_xref(name:"URL", value:"https://www.manageengine.com/products/netflow/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8060);

url = "/";
res = http_get_cache(port: port, item: url);
if (">NetFlow Analyzer<" >!< res || "ManageEngine" >!< res) {
  url = "/apiclient/ember/Login.jsp";
  res = http_get_cache(port: port, item: url);
  if ("NetFlow Analyzer" >!< res || "'info'>The Complete Traffic Analytics Software" >!< res)
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "manageengine/products/detected", value: TRUE);
set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
set_kb_item(name: "manageengine/netflow_analyzer/detected", value: TRUE);
set_kb_item(name: "manageengine/netflow_analyzer/http/detected", value: TRUE);

# SRC="/cachestart/125487/cacheend/apiclient/fluidicv2/javascript/jquery/jquery-3.5.1.min.js">
vers = eregmatch(pattern: "/cachestart/([0-9]+)/cacheend/", string: res);
if (!isnull(vers[1]))
  version = vers[1];

cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:zohocorp:manageengine_netflow_analyzer:");
if (!cpe)
  cpe = "cpe:/a:zohocorp:manageengine_netflow_analyzer";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "ManageEngine NetFlow Analyzer", version: version,
                                         install: location, cpe: cpe, concluded: vers[0],
                                         concludedUrl: conclUrl),
            port: port);

exit(0);
