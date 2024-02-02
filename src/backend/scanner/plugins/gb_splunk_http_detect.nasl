# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100693");
  script_version("2024-01-29T05:05:18+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-01-29 05:05:18 +0000 (Mon, 29 Jan 2024)");
  script_tag(name:"creation_date", value:"2010-07-05 12:40:56 +0200 (Mon, 05 Jul 2010)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Splunk Enterprise Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8000);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection Splunk Enterprise.");

  script_xref(name:"URL", value:"https://www.splunk.com/en_us/products/splunk-enterprise.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 8000);

foreach dir (make_list_unique("/", "/splunk/en-US", "/en-US", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url = dir + "/account/login";

  res1 = http_get_cache(port: port, item: url);

  if (egrep(pattern: 'content="Splunk Inc."', string: res1, icase: TRUE) &&
      ("Splunk Enterprise" >< res1 || res1 =~ 'product_type"\\s*:\\s*"enterprise')) {
    version = "unknown";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # &copy; 2005-2024 Splunk Inc. Splunk 6.0.2
    vers = eregmatch(string: res1, pattern: "&copy;.*Splunk ([0-9.]+)", icase: TRUE);
    if (isnull(vers[1]))
      # "version":"6.5.3"
      vers = eregmatch(string: res1, pattern: 'version":"([0-9.]+)', icase: TRUE);

    if (!isnull(vers[1]))
      version = vers[1];

    # <p class="footer">&copy; 2005-2024 Splunk Inc. Splunk 6.0.2 build 196940.</p>
    # <p class="footer">&copy; 2005-2024 Splunk Inc. Splunk 6.0 build 182037.</p>
    b = eregmatch(string: res1, pattern: "&copy;.*Splunk.* build ([0-9.]+)", icase: TRUE);
    if (isnull(b[1]))
      b = eregmatch(string: res1, pattern:'build":"([0-9a-z.]+)', icase: TRUE);

    if (!isnull(b[1])) {
      build = b[1];
      # nb: Removes a possible trailing dot from the build (see example above)
      build = ereg_replace(string: build, pattern: "\.$", replace: "");
    }

    if (version == "unknown") {
      url = dir + "/help";

      res2 = http_get_cache(port: port, item: url);

      # var args = {"location": "", "license": "pro", "installType": "prod", "versionNumber": "9.0.1", "skin": "default", "locale": "en-US", "product": "splunk", "response_type": "json"};
      vers = eregmatch(pattern: '"versionNumber"\\s*:\\s*"([0-9.]+)"', string: res2);
      if (!isnull(vers[1])) {
        version = vers[1];
        conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }

    set_kb_item(name: "splunk/detected", value: TRUE);
    set_kb_item(name: "splunk/http/detected", value: TRUE);

    # In many cases the OS is also exposed like e.g. the following for later 6.x versions (e.g.
    # 6.4.1) and any 7.x, 8.x or 9.x version:
    #
    # "master_guid":"<redacted>","os_name":"Linux"}}]
    # "master_guid":"<redacted>","os_name":"Windows"}}]
    # "master_guid":"<redacted>","os_name":"Linux","product_type":"enterprise","instance_type":"download"}}]
    #
    # and for this for earlier 6.x versions like e.g. 6.0.2:
    #
    # {"cpu_arch": "x86_64", "os_name": "Linux", "installType": "prod",
    #
    if (os_name = eregmatch(string: res1, pattern:'"os_name"\\s*:\\s*"[^"]+"', icase: FALSE)) {

      banner_type = "Splunk Enterprise 'os_name' Page Content";

      if (os_name =~ "Linux")
        os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", port: port, banner_type: banner_type, banner: os_name[0], desc: "Splunk Enterprise Detection (HTTP)", runs_key: "unixoide");
      else if (os_name =~ "Windows")
        os_register_and_report(os: "Windows", cpe: "cpe:/o:microsoft:windows", port: port, banner_type: banner_type, banner: os_name[0], desc: "Splunk Enterprise Detection (HTTP)", runs_key: "windows");
      else
        os_register_unknown_banner(banner: os_name[0], banner_type_name: banner_type, banner_type_short: "splunk_enterprise_os_name", port: port);
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:splunk:splunk:");
    if (!cpe)
      cpe = "cpe:/a:splunk:splunk";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Splunk Enterprise", version: version, build: build,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: conclUrl),
                port: port);
    exit(0);
  }
}

exit(0);
