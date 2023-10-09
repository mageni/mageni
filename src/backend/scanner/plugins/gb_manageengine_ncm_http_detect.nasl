# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140774");
  script_version("2023-08-18T05:05:27+0000");
  script_tag(name:"last_modification", value:"2023-08-18 05:05:27 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-02-15 15:59:46 +0700 (Thu, 15 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ManageEngine Network Configuration Manager Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8060);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ManageEngine Network Configuration
  Manager.");

  script_xref(name:"URL", value:"https://www.manageengine.com/network-configuration-manager/");

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
if (">Network Configuration Manager<" >!< res || "ManageEngine" >!< res) {
  url = "/apiclient/ember/Login.jsp";
  res = http_get_cache(port: port, item: url);
  if ("Configuration Manager" >!< res || "'info'>Network Configuration & Change Management Software" >!< res)
    exit(0);
}

version = "unknown";
location = "/";
conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

set_kb_item(name: "manageengine/products/detected", value: TRUE);
set_kb_item(name: "manageengine/products/http/detected", value: TRUE);
set_kb_item(name: "manageengine/ncm/detected", value: TRUE);
set_kb_item(name: "manageengine/ncm/http/detected", value: TRUE);

# <link href="/cachestart/127109/cacheend/apiclient/fluidicv2/styles/css/commonstyles.css"
vers = eregmatch(pattern: "/cachestart/([0-9]+)/cacheend/", string: res);
if (!isnull(vers[1]))
  version = vers[1];

cpe = build_cpe(value: version, exp: "^([0-9]+)", base: "cpe:/a:zohocorp:manageengine_network_configuration_manager:");
if (!cpe)
  cpe = "cpe:/a:zohocorp:manageengine_network_configuration_manager";

register_product(cpe: cpe, location: location, port: port, service: "www");

log_message(data: build_detection_report(app: "ManageEngine Network Configuration Manager", version: version,
                                         install: location, cpe: cpe, concluded: vers[0],
                                         concludedUrl: conclUrl),
            port: port);

exit(0);
