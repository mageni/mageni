# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141450");
  script_version("2023-10-19T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-10-19 05:05:21 +0000 (Thu, 19 Oct 2023)");
  script_tag(name:"creation_date", value:"2018-09-07 10:45:04 +0700 (Fri, 07 Sep 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Red Hat OpenShift Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Red Hat OpenShift.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.openshift.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

port = http_get_port(default: 443);

version = "unknown";
install = "/";
url = "/";

res = http_get_cache(port: port, item: url);

if (concl = egrep(string: res, pattern:"<title>Red Hat OpenShift</title>", icase: FALSE)) {
  found = TRUE;
  concl = chomp(concl);
  concl = "  " + ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
  concUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

  # "releaseVersion":"4.13.4"
  vers = eregmatch(pattern: '"releaseVersion"\\s*:\\s*"([0-9.]+)([^"]*)"', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concl += '\n  ' + vers[0];
  }
} else {
  url = "/console/";
  res = http_get_cache(port: port, item: url);

  if (concl = egrep(string: res, pattern:"<title>OpenShift Web Console</title>", icase: FALSE)) {
    found = TRUE;
    concl = "  " + chomp(concl);
    concUrl = "  " + http_report_vuln_url(port: port, url: url, url_only: TRUE);

    url = "/console/config.js";
    res = http_get_cache(port: port, item: url);

    # openshift: "v3.7.2+cd74924-1"
    # openshift: "v3.6.173.0.123"
    # openshift: "v1.4.1"
    vers = eregmatch(pattern: 'openshift\\s*:\\s*"v([0-9.]+)([^"]*)"', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concl += '\n  ' + vers[0];
      concUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
    } else {

      # console: "v3.11.0+ea42280"
      # console: "v3.11.154"
      # console: "v3.11.146"
      # console: "3.11.685-1.gd742e61-d742e61"
      vers = eregmatch(pattern: 'console\\s*:\\s*"(v)?([0-9.]+)([^"]*)"', string: res);
      if (!isnull(vers[2])) {
        version = vers[2];
        concl += '\n  ' + vers[0];
        concUrl += '\n  ' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }
  }
}

if (found) {
  set_kb_item(name: "redhat/openshift/detected", value: TRUE);
  set_kb_item(name: "redhat/openshift/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:redhat:openshift:");
  if (!cpe)
    cpe = "cpe:/a:redhat:openshift";

  # nb: Seems to only run / is supported on RHEL according to:
  # - https://docs.openshift.com/container-platform/3.11/install/prerequisites.html
  # - https://en.wikipedia.org/wiki/OpenShift
  os_register_and_report(os: "Red Hat Enterprise Linux", cpe: "cpe:/o:redhat:enterprise_linux", port: port,
                         banner_type: "Red Hat OpenShift Web Console", desc: "Red Hat OpenShift Detection (HTTP)", runs_key: "unixoide");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Red Hat OpenShift", version: version, install: install, cpe: cpe,
                                           concluded: concl, concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
