###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lexmark_printers_detect.nasl 12260 2018-11-08 12:46:52Z cfischer $
#
# Lexmark Printer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103685");
  script_version("$Revision: 12260 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-08 13:46:52 +0100 (Thu, 08 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-03-28 11:31:24 +0100 (Thu, 28 Mar 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Lexmark Printer Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  # nb: Don't use http_version.nasl as the Detection should run as early
  # as possible if the printer should be marked dead as requested.
  script_dependencies("find_service.nasl", "httpver.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Lexmark Printers.

  The script sends a connection request to the remote host and attempts to detect if the remote host is a Lexmark
  printer.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("lexmark_printers.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

urls = get_lexmark_detect_urls();

foreach url(keys(urls)) {

  pattern = url;
  url = urls[url];

  buf = http_get_cache(item:url, port:port);

  if(lex = eregmatch(pattern:pattern, string:buf, icase:TRUE)) {

    if(!isnull(lex[1])) {

      concluded = lex[0];
      model     = chomp(lex[1]);
      version = "unknown";

      set_kb_item(name:"target_is_printer", value:TRUE);
      set_kb_item(name:"lexmark_printer/installed", value:TRUE);
      set_kb_item(name:"lexmark_printer/port", value:port);
      set_kb_item(name:"lexmark_model", value:model);

      url = '/cgi-bin/dynamic/printer/config/reports/deviceinfo.html';
      headers =  make_array("Cookie", "lexlang=0;");	# language should be english
      req = http_get_req(port: port, url: url, add_headers: headers);
      res = http_keepalive_send_recv(port: port, data: req);

      # >Base</p></td><td><p> =  LW63.GM2.P641-0 </p></td>
      vers = eregmatch(pattern: '>Base</p></td><td><p> =  ([^ ]+)', string: res);
      if (!isnull(vers[1])) {
        version = vers[1];
        concUrl = url;
        cpe_version = str_replace(string: version, find: "-", replace: ".");
      }
      else {
        url = '/webglue/content?c=%2FStatus&lang=en';
        res = http_get_cache(port: port, item: url);

        vers = eregmatch(pattern: 'Firmware Level.*<span class="untranslated">([^<]+)', string: res);
        if (!isnull(vers[1])) {
          version = vers[1];
          concUrl = url;
        }
      }

      cpe_model = tolower(model);
      cpe_model = str_replace(string:cpe_model, find:" series", replace:"");

      cpe = build_cpe(value: cpe_version, exp: "^([A-Z0-9.]+)", base: 'cpe:/h:lexmark:' + cpe_model + ':');
      if (!cpe)
        cpe = 'cpe:/h:lexmark:' + cpe_model;

      register_product(cpe:cpe, location:"/", port:port, service:"www");

      log_message(data: build_detection_report(app: "Lexmark " + model, version: version, install: "/", cpe: cpe,
                                               concluded: vers[0], concludedUrl: concUrl),
                  port: port);

      pref = get_kb_item("global_settings/exclude_printers");
      if(pref == "yes") {
        log_message(port:port, data:'The remote host is a printer. The scan has been disabled against this host.\nIf you want to scan the remote host, uncheck the "Exclude printers from scan" option and re-scan it.');
        set_kb_item(name:"Host/dead", value:TRUE);
      }
      exit(0);
    }
  }
}

exit(0);
