# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149595");
  script_version("2023-05-04T09:51:03+0000");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-28 05:06:15 +0000 (Fri, 28 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("MailEnable Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of MailEnable.");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_asp(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/mewebmail", "/mail", "/webmail", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/Mondo/lang/sys/login.aspx";

  res = http_get_cache(port: port, item: url);

  if ("<title>MailEnable" >< res && "login_panel" >< res) {
    version = "unknown";

    set_kb_item(name: "mailenable/detected", value: TRUE);
    set_kb_item(name: "mailenable/http/detected", value: TRUE);
    set_kb_item(name: "mailenable/http/port", value: port);
    set_kb_item(name: "mailenable/http/" + port + "/location", value: install);
    set_kb_item(name: "mailenable/http/" + port + "/concludedUrl",
                value: http_report_vuln_url(port: port, url: url, url_only: TRUE));

    # me.css?v=10.43
    vers = eregmatch(pattern: "\.css\?v=([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      set_kb_item(name: "mailenable/http/" + port + "/concluded", value: vers[0]);
    }

    set_kb_item(name: "mailenable/http/" + port + "/version", value: version);
    exit(0);
  }
}

if (!banner = http_get_remote_headers(port: port))
  exit(0);

# nb: Just a last fallback if the detection from the previous code failed
if (concl = egrep(string: banner, pattern: "^[Ss]erver\s*:\s*MailEnable-HTTP", icase: FALSE)) {
  version = "unknown";
  install = "/";
  concl = chomp(concl);

  set_kb_item(name: "mailenable/detected", value: TRUE);
  set_kb_item(name: "mailenable/http/detected", value: TRUE);
  set_kb_item(name: "mailenable/http/port", value: port);
  set_kb_item(name: "mailenable/http/" + port + "/location", value: install);
  set_kb_item(name: "mailenable/http/" + port + "/concludedUrl",
              value: http_report_vuln_url(port: port, url: install, url_only: TRUE));
  set_kb_item(name: "mailenable/http/" + port + "/concluded", value: concl);
  set_kb_item(name: "mailenable/http/" + port + "/version", value: version);
}

exit(0);
