# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805661");
  script_version("2023-09-15T16:10:33+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-09-15 16:10:33 +0000 (Fri, 15 Sep 2023)");
  script_tag(name:"creation_date", value:"2015-06-19 10:58:10 +0530 (Fri, 19 Jun 2015)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Adobe Connect Detection (HTTP)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Adobe Connect.");

  script_xref(name:"URL", value:"http://www.adobe.com/products/adobeconnect.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

url = "/system/login";

res = http_get_cache(port: port, item: url);

# <title>Adobe Connect Central Login</title>
# alt="ADOBE CONNECT" -> Seen on 9.x
# alt="Adobe Connect Logo" -> Seen on 10.x and later
if ("<title>Adobe Connect Central" >< res && res =~ 'alt="Adobe Connect') {
  version = "unknown";
  location = "/";
  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  set_kb_item(name: "adobe/connect/detected", value: TRUE);
  set_kb_item(name: "adobe/connect/http/detected", value: TRUE);

  # <a class="loginHelp" title="10.8.0" target="_blank" href="
  # <a class="loginHelp" title="9.1.1b" target="_blank" href="
  # <a class="loginHelp" title="12.1.5" target="_blank" rel="noopener noreferrer" href="
  vers = eregmatch(pattern: 'class="loginHelp"\\s+title="([0-9.]+)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
  } else {
    # src="/common/scripts/showContent.js?ver=10.8.0"
    # src="/common/scripts/showContent.js?ver=9.1.1b"
    # src="/common/scripts/showContent.js?ver=12.1.5"
    vers = eregmatch(pattern: "\.(css|js)\?ver=([0-9.]+)", string: res);
    if (!isnull(vers[2]))
      version = vers[2];
  }

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:adobe:connect:");
  if (!cpe)
    cpe = "cpe:/a:adobe:connect";

  os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                         desc: "Adobe Connect Detection (HTTP)", runs_key: "windows");

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Adobe Connect", version: version, install: location,
                                           cpe: cpe, concluded: vers[0], concludedUrl: conclUrl),
              port: port);
  exit(0);
}

exit(0);
