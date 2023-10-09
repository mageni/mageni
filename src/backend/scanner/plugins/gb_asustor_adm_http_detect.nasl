# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141250");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-29 13:36:40 +0200 (Fri, 29 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("ASUSTOR Data Master (ADM) Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of ASUSTOR Data Master (ADM).");

  script_xref(name:"URL", value:"https://www.asustor.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 8000);

url = "/portal/";

res = http_get_cache(port: port, item: url);

if ("login-nas-model" >< res && "nasModel =" >< res && "fwType = " >< res) {
  version = "unknown";
  location = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # nasModel ='AS3102T',
  mod = eregmatch(pattern: "nasModel ='([^']+)", string: res);
  if (!isnull(mod[1])) {
    model = mod[1];
    set_kb_item(name: "asustor/adm/model", value: model);
  }

  # var _dcTag = '3.1.2.RHG1',
  vers = eregmatch(pattern: "var _dcTag = '([^']+)'", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "asustor/adm/detected", value: TRUE);
  set_kb_item(name: "asustor/adm/http/detected", value: TRUE);

  cpe = build_cpe(value: tolower(version), exp: "^([0-9a-z.]+)", base: "cpe:/a:asustor:adm:");
  if (!cpe)
    cpe = "cpe:/a:asustor:adm";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "ASUSTOR Data Master " + model, version: version,
                                           install: location, cpe: cpe, concluded: vers[0],
                                           concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
