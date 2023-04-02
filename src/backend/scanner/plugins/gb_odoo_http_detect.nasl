# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812511");
  script_version("2023-03-28T10:09:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-28 10:09:39 +0000 (Tue, 28 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-02-08 11:46:24 +0530 (Thu, 08 Feb 2018)");
  script_name("Odoo Business Management Software Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.odoo.com/");

  script_tag(name:"summary", value:"HTTP based detection of the Odoo business management
  software.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

foreach dir(make_list_unique("/", "/Odoo", "/odoo_cms", "/odoo_cmr", "/CMR", http_cgi_dirs(port:port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  res = http_get_cache(item:dir + "/web/login", port:port);

  if("Log in with Odoo.com" >< res && (res =~ '(P|p)owered by.*>Odoo' || 'content="Odoo' >< res) &&
     ">Log in" >< res) {

    version = "unknown";

    set_kb_item(name:"odoo/detected", value:TRUE);
    set_kb_item(name:"odoo/http/detected", value:TRUE);

    cpe = "cpe:/a:odoo:odoo";

    register_product(cpe:cpe, location:install, port:port, service:"www");

    log_message(data:build_detection_report(app:"Odoo",
                                            version:version,
                                            install:install,
                                            cpe:cpe),
                port:port);
    exit(0);
  }
}

exit(0);
