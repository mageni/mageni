# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900822");
  script_version("2023-06-23T16:09:17+0000");
  script_tag(name:"last_modification", value:"2023-06-23 16:09:17 +0000 (Fri, 23 Jun 2023)");
  script_tag(name:"creation_date", value:"2009-08-26 14:01:08 +0200 (Wed, 26 Aug 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Adobe JRun Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 8000);
  script_mandatory_keys("adobe/jrun/banner");

  script_tag(name:"summary", value:"HTTP based detection of Adobe JRun (formerly maintained by
  Allaire and Macromedia).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:8000);

urls = make_array(
  # Server: JRun Web Server
  # Server: JRun Web Server/3.0
  # <head><title>JRun Servlet Error</title></head><h1>500 </h1><body>
  # nb: Should be kept as the first entry as this might include a version string
  "/", "(^[Ss]erver\s*:\s*JRun Web Server|<title>JRun Servlet Error</title>)",
  # nb: The next two URLs and the last pattern got taken from pre2008/DDI_JRun_Sample_Files.nasl
  "/docs/servlets/index.html", "(^[Ss]erver\s*:\s*JRun Web Server|<title>JRun Servlet Error</title>|JRun Servlet Engine)",
  "/jsp/index.html", "(^[Ss]erver\s*:\s*JRun Web Server|<title>JRun Servlet Error</title>|JRun Scripting Examples)"
);

foreach url(keys(urls)) {

  pattern = urls[url];

  res = http_get_cache(item:url, port:port);

  if(concl = egrep(pattern:pattern, string:res, icase:FALSE)) {

    concluded = chomp(concl);
    concludedUrl = http_report_vuln_url(port:port, url:url, url_only:TRUE);
    install = "/";
    version = "unknown";

    vers = eregmatch(pattern:">Version ([0-9.]+)", string:res, icase:FALSE);
    if(vers) {
      version = vers[1];
      concluded += '\n' + vers[0];
    }

    if(version == "unknown") {
      vers = eregmatch(pattern:"[Ss]erver\s*:\s*JRun Web Server/([0-9.]+)", string:res, icase:FALSE);
      # nb: No need to add this to the "concluded" string as it is already included there
      if(vers)
        version = vers[1];
    }

    set_kb_item(name:"adobe/jrun/detected", value:TRUE);
    set_kb_item(name:"adobe/jrun/http/detected", value:TRUE);

    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:adobe:jrun:");
    if(!cpe)
      cpe = "cpe:/a:adobe:jrun";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Adobe JRun",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concludedUrl:concludedUrl,
                                            concluded:concluded),
                port:port);
    exit(0);
  }
}

exit(0);
