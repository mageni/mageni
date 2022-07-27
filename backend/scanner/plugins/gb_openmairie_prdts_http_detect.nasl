# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.800779");
  script_version("2021-08-04T02:26:48+0000");
  script_tag(name:"last_modification", value:"2021-08-05 10:56:26 +0000 (Thu, 05 Aug 2021)");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("OpenMairie Product Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of OpenMairie products.");

  script_xref(name:"URL", value:"http://www.openmairie.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

list = make_list_unique("/openmairie_annuaire", "/Openmairie_Annuaire",
                        "/openmairie_courrier","/Openmairie_Courrier",
                        "/openmairie_planning", "/Openmairie_Planning",
                        "/openmairie_presse", "/Openmairie_Presse",
                        "/openmairie_cominterne", "/Openmairie_Cominterne",
                        "/openmairie_foncier", "/Openmairie_Foncier",
                        "/openmairie_registreCIL", "/Openmairie_RegistreCIL",
                        "/openmairie_cimetiere", "/Openmairie_Cimetiere",
                        "/", "/scr", http_cgi_dirs(port: port));

foreach dir (list) {

  install = dir;
  if (dir == "/")
    dir = "";

  url1 = dir + "/index.php";
  url2 = dir + "/login.php";

  res1 = http_get_cache(port: port, item: url1);
  res2 = http_get_cache(port: port, item: url2);

  if (">Open Annuaire&" >< res1) {
    version = "unknown";

    vers = eregmatch(pattern: "Version&nbsp;([0-9.]+)", string: res1);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "openmairie/products/detected", value: TRUE);
    set_kb_item(name: "openmairie/open_annuaire/detected", value: TRUE);
    set_kb_item(name: "openmairie/open_annuaire/http/detected", value: TRUE);

    concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openannuaire:");
    if (!cpe)
      cpe = "cpe:/a:openmairie:openannuaire";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "OpenMairie Open Annuaire", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: concUrl),
                port: port);
  }

  if (">Open Courrier&" >< res1 || "openCourrier<" >< res2) {
    version = "unknown";

    vers = eregmatch(pattern: "Version&nbsp;([0-9.]+)([a-z]*)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
    } else {
      # openCourrier Version 3.3.1
      vers = eregmatch(pattern: "openCourrier Version ([0-9.]+)", string: res2);
      if (!isnull(vers[1])) {
        version = vers[1];
        concUrl = http_report_vuln_url(port: port, url: url2, url_only: TRUE);
      }
    }

    set_kb_item(name: "openmairie/products/detected", value: TRUE);
    set_kb_item(name: "openmairie/open_courrier/detected", value: TRUE);
    set_kb_item(name: "openmairie/open_courrier/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencourrier:");
    if (!cpe)
      cpe = "cpe:/a:openmairie:opencourrier";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "OpenMairie Open Courrier", version: version,
                                             install: install, cpe: cpe, concluded: vers[0],
                                             concludedUrl: concUrl),
                port: port);
  }

  if ("presse" >< res1) {
    vers = eregmatch(pattern: "> V e r s i o n ([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

      set_kb_item(name: "openmairie/products/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_presse/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_presse/http/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openpresse:");
      if (!cpe)
        cpe = "cpe:/a:openmairie:openpresse";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "OpenMairie Open Presse", version: version,
                                               install: install, cpe: cpe, concluded: vers[0],
                                               concludedUrl: concUrl),
                  port: port);
    }
  }

  if (">Open Planning&" >< res1) {
    vers = eregmatch(pattern: "Version&nbsp;([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

      set_kb_item(name: "openmairie/products/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_planning/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_planning/http/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openplanning:");
      if (!cpe)
        cpe = "cpe:/a:openmairie:openplanning";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "OpenMairie Open Planning", version: version,
                                               install: install, cpe: cpe, concluded: vers[0],
                                               concludedUrl: concUrl),
                  port: port);
    }
  }

  if ("Communication Interne" >< res1) {
    vers = eregmatch(pattern: "> V e r s i o n ([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

      set_kb_item(name: "openmairie/products/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_cominterne/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_cominterne/http/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencominterne:");
      if (!cpe)
        cpe = "cpe:/a:openmairie:oopencominterne";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "OpenMairie Open Communication Interne", version: version,
                                               install: install, cpe: cpe, concluded: vers[0],
                                               concludedUrl: concUrl),
                  port: port);
    }
  }

  if (">opencimetiere" >< res1 || res1 =~ " openCimeti.re<" || res2 =~ " openCimeti.re") {
    version = "unknown";

    vers = eregmatch(pattern: "Version&nbsp;([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
    } else {
      # openCimetiere Version 4.0.0
      vers = eregmatch(pattern: "openCimeti.re Version ([0-9.]+)", string: res1);
      if (!isnull(vers[1])) {
        version = vers[1];
        concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
      } else {
        # openCimetiere Version 3.0.0
        vers = eregmatch(pattern: "openCimeti.re Version ([0-9.]+)", string: res2);
        if (!isnull(vers[1])) {
          version = vers[1];
          concUrl = http_report_vuln_url(port: port, url: url2, url_only: TRUE);
        }
      }
    }

    set_kb_item(name: "openmairie/products/detected", value: TRUE);
    set_kb_item(name: "openmairie/open_cimetiere/detected", value: TRUE);
    set_kb_item(name: "openmairie/open_cimetiere/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencimetiere:");
    if (!cpe)
      cpe = "cpe:/a:openmairie:opencimetiere";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "OpenMairie Open Communication Interne", version: version,
                                            install: install, cpe: cpe, concluded: vers[0],
                                            concludedUrl: concUrl),
                  port: port);
  }

  if (">Open Registre CIL&" >< res1) {
    vers = eregmatch(pattern: "Version&nbsp;([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

      set_kb_item(name: "openmairie/products/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_registre/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_registre/http/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openregistrecil:");
      if (!cpe)
        cpe = "cpe:/a:openmairie:openregistrecil";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "OpenMairie Open Registre CIL", version: version,
                                               install: install, cpe: cpe, concluded: vers[0],
                                               concludedUrl: concUrl),
                  port: port);
     }
   }

  if (">openFoncier<" >< res1 || "Fonciere" >< res1) {
    vers = eregmatch(pattern: "Version&nbsp;([0-9.]+)", string: res1);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

      set_kb_item(name: "openmairie/products/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_foncier/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_foncier/http/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openfoncier:");
      if (!cpe)
        cpe = "cpe:/a:openmairie:openfoncier";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "OpenMairie Open Foncier", version: version,
                                               install: install, cpe: cpe, concluded: vers[0],
                                               concludedUrl: concUrl),
                  port: port);
    } else {
      vers = eregmatch(pattern: ">version ((beta)?.?([0-9.]+))", string: res1);
      if (!isnull(vers[1])) {
        version = ereg_replace(pattern: " ", string: vers[1], replace: ".");
        concUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);

        set_kb_item(name: "openmairie/products/detected", value: TRUE);
        set_kb_item(name: "openmairie/open_foncier/detected", value: TRUE);
        set_kb_item(name: "openmairie/open_foncier/http/detected", value: TRUE);

        cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:openfoncier:");
        if (!cpe)
          cpe = "cpe:/a:openmairie:openfoncier";

        register_product(cpe: cpe, location: install, port: port, service: "www");

        log_message(data: build_detection_report(app: "OpenMairie Open Foncier", version: version,
                                                 install: install, cpe: cpe, concluded: vers[0],
                                                 concludedUrl: concUrl),
                    port: port);
      }
    }
  }
}

foreach dir (make_list_unique("/openmairie_catalogue", "/Openmairie_Catalogue", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/doc/catalogue.html";

  res = http_get_cache(port: port, item: url);

  if ("OPENCATALOGUE" >< res || res =~ "[Cc]atalogue") {
    url = dir + "/index.php";
    res = http_get_cache(port: port, item: url);

    vers = eregmatch(pattern: "> V e r s i o n ([0-9.]+)", string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

      set_kb_item(name: "openmairie/products/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_catalogue/detected", value: TRUE);
      set_kb_item(name: "openmairie/open_catalogue/http/detected", value: TRUE);

      cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:openmairie:opencatalogue:");
      if (!cpe)
        cpe = "cpe:/a:openmairie:opencatalogue";

      register_product(cpe: cpe, location: install, port: port, service: "www");

      log_message(data: build_detection_report(app: "OpenMairie Open Foncier", version: version,
                                               install: install, cpe: cpe, concluded: vers[0],
                                               concludedUrl: concUrl),
                  port: port);
    }
  }
}

exit(0);
