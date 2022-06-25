# Copyright (C) 2013 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103735");
  script_version("2022-03-14T16:13:11+0000");
  script_tag(name:"last_modification", value:"2022-03-15 11:02:07 +0000 (Tue, 15 Mar 2022)");
  script_tag(name:"creation_date", value:"2013-06-12 11:17:19 +0200 (Wed, 12 Jun 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Plone CMS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Plone CMS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://plone.org/");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default: 80);

detection_patterns = make_list(
  '<div xmlns:css="https?://namespaces\\.plone\\.org/diazo/css"',
  "/\+\+plone\+\+static/plone-compiled\.css",
  "/\+\+plone\+\+static/tinymce-styles\.css",
  # <a href="http://plone.com" target="_blank" title="This site was built using the Plone Open Source CMS/WCM.">Powered by Plone &amp; Python</a>
  # "Powered by Plone & Python":"Powered by Plone & Python"
  '[>"]Powered by Plone &(amp;)? Python[<"]',
  # <meta name="generator" content="Plone 6 - https://plone.org"/>
  # <meta name="generator" content="Plone - http://plone.org" />
  # <meta name="generator" content="Plone - http://plone.com" />
  '<meta name="generator" content="Plone[^>]+>',
  # Server: Zope/(Zope 2.10.5-final, python 2.4.4, darwin) ZServer/1.1 Plone/3.1.1
  # Server: Zope/(Zope 2.8.6-final, python 2.3.5, linux2) ZServer/1.1 Plone/Unknown
  # Server: Zope/(Zope 2.9.9-final, python 2.4.6, linux4) ZServer/1.1 Plone/2.5.5
  # Server: Zope/(Zope 2.9.8-final, python 2.4.4, win32) ZServer/1.1 Plone/2.5.3-final
  '[Ss]erver\\s*:[^\r\n]*Plone/[^\r\n]+'
);

foreach dir (make_list_unique("/", "/plone", "/Plone", "/cms", http_cgi_dirs(port: port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  res = http_get_cache(item: dir + "/", port: port);
  if (!res || res !~ "^HTTP/1\.[01] 200")
    continue;

  found = 0;
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach detection_pattern (detection_patterns) {

    # nb: Don't use "egrep" because some systems are providing single line of HTML code which
    # would cause too much stuff to be reported in the concluded reporting...
    concl = eregmatch(string: res, pattern: detection_pattern, icase: FALSE);

    if (concl) {
      found++;
      if (concluded)
        concluded += '\n';
      concluded += "  " + concl[0];
    }
  }

  # nb: We're currently stopping with the first detection as at least the generator pattern had
  # caused hundreds of detections on the same system in the past.
  if (found > 0)
    break;
}

if (found > 0) {

  version = "unknown";
  conclUrl = http_report_vuln_url(port: port, url: install, url_only: TRUE);

  vers = eregmatch(pattern: '[Ss]erver\\s*:[^\r\n]*Plone/([0-9.]+)', string: res, icase: FALSE);
  if (!isnull(vers[1]))
    version = vers[1];

  set_kb_item(name: "plone/detected",value: TRUE);
  set_kb_item(name: "plone/http/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:plone:plone:");
  if (!cpe)
    cpe = "cpe:/a:plone:plone";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "Plone CMS", version: version, install: install, cpe: cpe,
                                           concludedUrl: conclUrl, concluded: concluded),
              port: port);
}

exit(0);
