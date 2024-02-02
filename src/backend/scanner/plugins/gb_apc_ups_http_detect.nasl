# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151361");
  script_version("2023-12-08T16:09:30+0000");
  script_tag(name:"last_modification", value:"2023-12-08 16:09:30 +0000 (Fri, 08 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-07 07:06:39 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("APC UPS Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of APC UPS devices / network management
  cards.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/logon.htm";

res = http_get_cache(port: port, item: url);

if ("<title>APC | Log On</title>" >< res || 'alt="APC Website"' >< res || "http://www.apc.com" >< res) {
  model_type = "unknown";
  model = "unknown";
  version = "unknown";

  set_kb_item(name: "apc/ups/detected", value: TRUE);
  set_kb_item(name: "apc/ups/http/detected", value: TRUE);
  set_kb_item(name: "apc/ups/http/port", value: port);
  set_kb_item(name: "apc/ups/http/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

  set_kb_item(name: "apc/ups/http/" + port + "/model_type", value: model_type);
  set_kb_item(name: "apc/ups/http/" + port + "/model", value: model);
  set_kb_item(name: "apc/ups/http/" + port + "/version", value: version);
}

exit(0);
