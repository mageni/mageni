# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140887");
  script_version("2023-05-16T09:08:27+0000");
  script_tag(name:"last_modification", value:"2023-05-16 09:08:27 +0000 (Tue, 16 May 2023)");
  script_tag(name:"creation_date", value:"2018-03-27 08:53:26 +0700 (Tue, 27 Mar 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("etcd Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2379);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of etcd.");

  script_xref(name:"URL", value:"https://etcd.io/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 2379);

url = "/version";
res = http_get_cache(port: port, item: url);

if ('"etcdserver":' >< res) {
  version = "unknown";
  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # {"etcdserver":"3.1.7","etcdcluster":"3.1.0"}
  vers = eregmatch(pattern: '"etcdserver":"([0-9.]+)', string: res);
  if (!isnull(vers[1]))
    version = vers[1];

  # nb: Get some additional statistics
  url = "/v2/stats/self";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # Name
  data = eregmatch(pattern: '"name":"([^"]+)', string: res);
  if (!isnull(data[1])) {
    extra += "  Name:    " + data[1] + '\n';
    concUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  # Uptime
  data = eregmatch(pattern: '"uptime":"([^"]+)', string: res);
  if (!isnull(data[1]))
    extra += "  Uptime:  " + data[1];

  set_kb_item(name: "etcd/detected", value: TRUE);
  set_kb_item(name: "etcd/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:etcd:etcd:");
  if (!cpe)
    cpe = "cpe:/a:etcd:etcd";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "etcd", version: version, install: "/", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl, extra: extra),
              port: port);
  exit(0);
}

exit(0);
