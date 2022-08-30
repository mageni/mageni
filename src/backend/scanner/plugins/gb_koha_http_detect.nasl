# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148632");
  script_version("2022-08-25T12:58:36+0000");
  script_tag(name:"last_modification", value:"2022-08-25 12:58:36 +0000 (Thu, 25 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-24 07:21:52 +0000 (Wed, 24 Aug 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Koha Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Koha Library Software.");

  script_xref(name:"URL", value:"https://koha-community.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";

res = http_get_cache(port: port, item: url);

if (res && res =~ "^HTTP/1\.[01] 200" &&
    concl = egrep(string: res, pattern: '(content="Koha|<title>Koha|Log in to Koha)', icase: FALSE)) {
  concluded = chomp(concl);
  found = TRUE;
}

if (!found) {

  url = "/cgi-bin/koha/opac-search.pl";

  res = http_get_cache(port: port, item: url);
  if (res && res =~ "^HTTP/1\.[01] 200" &&
      concl = egrep(string: res, pattern: '(content="Koha|<title>Koha)', icase: FALSE)) {
    concluded = chomp(concl);
    found = TRUE;
  }
}

# nb: An old VT from 2011 had tested for the following on "/opac-main.pl":
# if("koha" >< res && "Library" >< res)
# Another one from 2015 had tested for the following on "/":
# if("Log in to Koha" >< res || res =~ "Powered by.*Koha") {
# If we're ever hitting some non-detected installations we might want to check this out.

if (found) {

  version = "unknown";
  install = "/";

  # name="generator" content="Koha 19.1125000"
  vers = eregmatch(pattern: '"generator"\\s+content="Koha\\s*([0-9.]+)', string: res);
  if (isnull(vers[1])) {
    # css/login_18.0502000.css
    vers = eregmatch(pattern: "login_([0-9]+\.[0-9]+)\.css", string: res);
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    # nb: Only add if not already existing from the previous grep
    if (vers[0] >!< concluded)
      concluded += '\n' + vers[0];
  }

  set_kb_item(name: "koha/detected", value: TRUE);
  set_kb_item(name: "koha/http/detected", value: TRUE);

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:koha:koha:");
  if (!cpe)
    cpe = "cpe:/a:koha:koha";

  os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Koha Detection (HTTP)",
                         runs_key: "unixoide");

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Koha", version: version, install: install, cpe: cpe,
                                           concluded: concluded, concludedUrl: concUrl),
              port: port);
}

exit(0);
