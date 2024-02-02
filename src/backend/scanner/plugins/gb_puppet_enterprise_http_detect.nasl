# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106362");
  script_version("2023-12-26T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-26 05:05:23 +0000 (Tue, 26 Dec 2023)");
  script_tag(name:"creation_date", value:"2016-11-01 13:44:38 +0700 (Tue, 01 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Puppet Enterprise Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Puppet Enterprise.");

  script_xref(name:"URL", value:"https://www.puppet.com/products/puppet-enterprise");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

req = http_get(port: port, item: "/auth/login?redirect=/");
res = http_keepalive_send_recv(port: port, data: req);

if ((concl = egrep(pattern: "Log In \| Puppet Enterprise", string: res, icase: TRUE)) && "usernameError" >< res) {
  version = "unknown";
  concluded = chomp(concl);
  vers = eregmatch(pattern: "([0-9.]+)/install_system_requirements.html", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    concluded += '\n' + vers[0];
    set_kb_item(name: "puppet_enterprise/version", value: version);
  }

  set_kb_item(name: "puppet_enterprise/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:puppet:enterprise:");
  if (!cpe)
    cpe = "cpe:/a:puppet:enterprise";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Puppet Enterprise", version: version, install: "/", cpe: cpe,
                                           concluded: concluded),
              port: port);
  exit(0);
}

exit(0);
