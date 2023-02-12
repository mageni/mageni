# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106794");
  script_version("2023-01-16T10:11:20+0000");
  script_tag(name:"last_modification", value:"2023-01-16 10:11:20 +0000 (Mon, 16 Jan 2023)");
  script_tag(name:"creation_date", value:"2017-04-27 14:38:21 +0200 (Thu, 27 Apr 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SilverStripe CMS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of the SilverStripe CMS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.silverstripe.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", "/silverstripe-cms", "/silverstripe", "/Silverstripe-cms", "/Silverstripe", "/cms", http_cgi_dirs(port: port))) {

  found = FALSE;
  conclUrl = NULL;
  concluded = NULL;
  install = dir;
  if (dir == "/")
    dir = "";

  url1 = dir + "/";
  res1 = http_get_cache(port: port, item: url1);
  url2 = dir + "/index.php";
  res2 = http_get_cache(port: port, item: url2);
  url3 = dir + "/Security/login";
  res3 = http_get_cache(port: port, item: url3);

  # nb: For systems from around 2017+ (initial implementation of this detection) up to a recent 4.11
  # version. Only difference was seen in the "SilverStripe" vs. "Silverstripe" generator tag...
  #
  # e.g.:
  # <meta name="generator" content="SilverStripe - http://silverstripe.org" />
  # <meta name="generator" content="Silverstripe CMS 4.11" />
  # <meta name="generator" content="Silverstripe CMS" />
  #
  if (res1 =~ "^HTTP/1\.[01] 200" && res3 =~ "^HTTP/1\.[01] 200" &&
      (concl = egrep(string: res1, pattern: '<meta name="generator" content="Silver[Ss]tripe', icase: FALSE)) &&
      "MemberLoginForm_LoginForm" >< res3) {

    conclUrl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
    conclUrl += '\n' + http_report_vuln_url(port: port, url: url3, url_only: TRUE);

    found = TRUE;
    concluded = chomp(concl);
    concluded = ereg_replace(string: concluded, pattern: "^(\s+)", replace: "");
  }

  # nb: Another fallback if the login URL is blocked. Second "full" string looks like e.g.:
  # <body class="HomePage no-sidebar" dir="ltr">
  if (res1 =~ "^HTTP/1\.[01] 200" &&
      (concl = egrep(string: res1, pattern: '<meta name="generator" content="Silver[Ss]tripe', icase: FALSE)) &&
      'class="HomePage' >< res1) {

    # nb: Only add the URL and concluded string to the reporting if not included previously...
    if (!found) {
      conclUrl += '\n' + http_report_vuln_url(port: port, url: url1, url_only: TRUE);
      concluded = chomp(concl);
      concluded = ereg_replace(string: concluded, pattern: "^(\s+)", replace: "");
    }

    found = TRUE;
  }

  # nb: This was used initially in an active check from 2015 and was later moved into this detection
  # to increase coverage of older installations / versions.
  if (res2 =~ "^HTTP/1\.[01] 200" &&
      (concl = egrep(string: res2, pattern: 'content="Silver[Ss]tripe', icase: FALSE)) &&
      "<title>Home" >< res2) {

    conclUrl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);

    # nb: Only add the concluded string to the reporting if not included previously...
    if (!found) {
      concluded = chomp(concl);
      concluded = ereg_replace(string: concluded, pattern: "^(\s+)", replace: "");
    }

    found = TRUE;
  }

  if (found) {

    version = "unknown";

    set_kb_item(name: "silverstripe_cms/detected", value: TRUE);
    set_kb_item(name: "silverstripe_cms/http/detected", value: TRUE);

    # nb: This is only the major.minor version (probably only available since 4.x) and currently
    # can't be used for reliable version checks. As it wasn't clear if older 3.x versions also
    # exposed the version the "CMS" part was made optional...
    vers = eregmatch(string: res1, pattern: 'content="Silver[Ss]tripe( CMS)? ([0-9.]{3,})', icase: FALSE);
    if (vers[2])
      version = vers[2];

    # From https://stackoverflow.com/a/33538459
    # nb:
    # - we're overwriting the previous version here if we were able to gather it from here as it
    #   should be more detailed...
    # - this is usually not accessible but still trying to gather the version from it if possible
    # - seen only on 3.x versions so far
    # - There is also "/framework/silverstripe_version" but that seems to be about the Silverstripe
    #   Framework which seems to be a different thing
    url = dir + "/cms/silverstripe_version";
    res = http_get_cache(port: port, item: url);
    if (res && res =~ "^HTTP/1\.[01] 200") {

      body = http_extract_body_from_response(data: res);

      if (body) {
        # "just" e.g. the following in the body:
        # 3.1.15
        # 3.1.5
        #
        # nb: "{3,}" is used to make the check a little bit more strict
        vers = eregmatch(string: body, pattern: '^\\s*([0-9.]{3,})$', icase: FALSE);
        if (vers[1]) {
          version = vers[1];
          concluded += '\n' + vers[1];
          conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);
        }
      }
    }

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:silverstripe:silverstripe:");
    if (!cpe)
      cpe = "cpe:/a:silverstripe:silverstripe";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "SilverStripe CMS",
                                             version: version,
                                             install: install,
                                             concluded: concluded,
                                             concludedUrl: conclUrl,
                                             cpe: cpe),
                port: port);
  }
}

exit(0);
