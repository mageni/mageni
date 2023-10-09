# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813390");
  script_version("2023-08-25T05:06:04+0000");
  script_tag(name:"last_modification", value:"2023-08-25 05:06:04 +0000 (Fri, 25 Aug 2023)");
  script_tag(name:"creation_date", value:"2018-06-06 15:18:41 +0530 (Wed, 06 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brother Printers Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Brother printer devices.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("brother_printers.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default: 443);

urls = get_brother_detect_urls();

foreach url (keys(urls)) {
  pattern = urls[url];
  url = ereg_replace(string: url, pattern: "(#--avoid-dup[0-9]+--#)", replace: "");

  res = http_get_cache(port: port, item: url);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  if (match = eregmatch(pattern: pattern, string: res, icase: TRUE)) {
    set_kb_item(name: "brother/printer/detected", value: TRUE);
    set_kb_item(name: "brother/printer/http/detected", value: TRUE);
    set_kb_item(name: "brother/printer/http/port", value: port);

    model = "unknown";
    fw_version = "unknown";

    if (!isnull(match[1])) {
      model = match[1];
      set_kb_item(name: "brother/printer/http/" + port + "/modConcluded", value: match[0]);
      set_kb_item(name: "brother/printer/http/" + port + "/modConcludedUrl",
                  value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    vers = eregmatch(pattern: "Main&#32;Firmware&#32;Version</dt><dd>([A-Z]{1,2})</dd>", string: res);

    if (isnull(vers[1]))
      vers = eregmatch(pattern: "Firmware&#32;Version</dt><dd>([0-9.]+)</dd>", string: res);

    if (!isnull(vers[1])) {
        fw_version = vers[1];
        set_kb_item(name: "brother/printer/http/" + port + "/versConcluded", value: vers[0]);
        set_kb_item(name: "brother/printer/http/" + port + "/versConcludedUrl",
                    value: http_report_vuln_url(port: port, url: url, url_only: TRUE));
    }

    set_kb_item(name: "brother/printer/http/" + port + "/model", value: model);
    set_kb_item(name: "brother/printer/http/" + port + "/fw_version", value: fw_version);

    exit(0);
  }
}

exit(0);
