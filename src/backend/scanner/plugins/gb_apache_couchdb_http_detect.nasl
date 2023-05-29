# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100571");
  script_version("2023-05-10T09:37:12+0000");
  script_tag(name:"last_modification", value:"2023-05-10 09:37:12 +0000 (Wed, 10 May 2023)");
  script_tag(name:"creation_date", value:"2010-04-12 18:40:45 +0200 (Mon, 12 Apr 2010)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache CouchDB Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("CouchDB/banner");
  script_require_ports("Services/www", 5984);

  script_tag(name:"summary", value:"HTTP based detection of Apache CouchDB.");

  script_xref(name:"URL", value:"http://couchdb.apache.org/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:5984);
banner = http_get_remote_headers(port: port);
if(!banner || banner !~ "Server: CouchDB/" )
  exit(0);

set_kb_item(name: "apache/couchdb/detected", value:TRUE);
set_kb_item(name: "apache/couchdb/http/detected", value:TRUE);
vers = "unknown";
location = "/";

version = eregmatch(pattern:"[sS]erver: CouchDB/([^ ]+)", string: banner);

if(!isnull(version[1])) {

  vers = version[1];
  set_kb_item(name: "apache/couchdb/version", value: vers);
  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:apache:couchdb:");

  if (!cpe)
    cpe = "cpe:/a:apache:couchdb";

  register_product(cpe: cpe, location: location, port: port, service: "www");

  log_message(data: build_detection_report(app: "Apache CouchDB",
                                           version: vers,
                                           install: location,
                                           cpe: cpe,
                                           concluded: version[0]),
                                           port: port);
}

exit(0);
