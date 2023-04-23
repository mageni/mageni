# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140540");
  script_version("2023-04-17T10:09:22+0000");
  script_tag(name:"last_modification", value:"2023-04-17 10:09:22 +0000 (Mon, 17 Apr 2023)");
  script_tag(name:"creation_date", value:"2017-11-28 08:24:34 +0700 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Sitefinity CMS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Sitefinity CMS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.progress.com/sitefinity-cms");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("os_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(port: port, item: dir + "/");

  if ('name="Generator" content="Sitefinity' >< res) {
    version = "unknown";

    vers = eregmatch(pattern: 'name="Generator" content="Sitefinity ([0-9.]+)', string: res);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "sitefinity/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:progress:sitefinity:");
    if (!cpe)
      cpe = "cpe:/a:progress:sitefinity";

    # Only Microsoft Windows according to:
    # https://www.progress.com/documentation/sitefinity-cms/system-requirements
    os_register_and_report(os: "Microsoft Windows", cpe: "cpe:/o:microsoft:windows", port: port,
                           desc: "Sitefinity CMS Detection (HTTP)", runs_key: "windows");

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Sitefinity CMS", version: version, install: install, cpe: cpe,
                                             concluded: vers[0]),
                port: port);
    exit(0);
  }
}

exit(0);
