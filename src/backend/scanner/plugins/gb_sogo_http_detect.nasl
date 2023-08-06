# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142120");
  script_version("2023-07-10T08:07:43+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:43 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"creation_date", value:"2019-03-11 16:02:17 +0700 (Mon, 11 Mar 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SOGo Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of SOGo.");

  script_xref(name:"URL", value:"https://sogo.nu/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/SOGo/";

res = http_get_cache(port: port, item: url);

if ('content="SOGo Web Interface"' >< res && "SOGo.woa" >< res) {
  version = "unknown";
  location = "/SOGo";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # <p>Version 4.0.4 (@shiva2.inverse 201812030202)</p>
  vers = eregmatch(pattern: "<p>Version ([0-9.]+)", string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "sogo/detected", value: TRUE);
  set_kb_item(name: "sogo/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:alinto:sogo:");
  if (!cpe)
    cpe = "cpe:/a:alinto:sogo";

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, runs_key: "unixoide",
                         desc: "SOGo Detection (HTTP)");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "SOGo", version: version, install: location, cpe: cpe,
                                           concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
