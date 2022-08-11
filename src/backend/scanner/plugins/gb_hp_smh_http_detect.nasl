# Copyright (C) 2009 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900657");
  script_version("2021-10-14T13:01:20+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-10-15 09:20:32 +0000 (Fri, 15 Oct 2021)");
  script_tag(name:"creation_date", value:"2009-06-01 09:35:57 +0200 (Mon, 01 Jun 2009)");
  script_name("HP/HPE System Management Homepage (SMH) Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 2301, 2381); # nb: 2301 is http, 2381 is https
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of HP/HPE System Management Homepage (SMH).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("cpe.inc");

# Due to the different pattern here we're using a count for them below.
detection_patterns = make_list(
  # Server: CompaqHTTPServer/9.9 HP System Management Homepage
  # Server: CompaqHTTPServer/9.9 HPE System Management Homepage
  # Server: CompaqHTTPServer/9.9 HPE System Management Homepage/7.6.3.3
  # Server: CompaqHTTPServer/9.9 HP System Management Homepage/6.2.0.13
  "^Server\s*:\s*.+HPE? System Management Homepage",

  # document.writeln("<title>HPE System Management Homepage - "+fullsystemname+"</title>");
  # document.writeln("<title>HP System Management Homepage - "+fullsystemname+"</title>");
  # nb: The one below happens for the 2301 -> 2381 redirect page
  # <title>HP System Management Homepage</title>
  "<title>HPE? System Management Homepage[^<]*</title>",

  # smhcopyright = "&copy; Copyright 2004,2018 Hewlett Packard Enterprise Development LP";
  # smhcopyright = "&copy; Copyright 2004-2012 Hewlett-Packard Development Company, L.P.";
  "^\s*smhcopyright\s*=.+",

  # <meta name="description" content="System Management Homepage" />
  '<meta name="description" content="System Management Homepage" />',

  # nb: Some systems are also redirecting from 2301 to 2381 by default via JS with a page like:
  #
  # <title>HP System Management Homepage</title>
  # *snip*
  # <p>This version of HP's management software has added new security features which
  # include only allowing access to the web-enabled interface using the secure HTTPS protocol.  This
  # protocol is accessed at a new port, 2381, instead of the port, 2301, used for HTTP access.</p>
  #
  # or:
  # <title>HPE System Management Homepage</title>
  # *snip*
  # <p>This version of HPE's management software has added new security features which
  # include only allowing access to the web-enabled interface using the secure HTTPS protocol.  This
  # protocol is accessed at a new port, 2381, instead of the port, 2301, used for HTTP access.</p>
  "<p>This version of HPE?'s management software");

ports = http_get_ports(default_port_list: make_list(2301, 2381));
foreach port (ports) {

  url = "/cpqlogin.htm";
  res = http_get_cache(port: port, item: url );
  banner = http_get_remote_headers(port: port);
  if (!res && !banner)
    continue;

  found = 0;
  conclurl = "";
  concluded = ""; # nb: To make openvas-nasl-lint happy...

  foreach pattern (detection_patterns) {

    if ("^Server" >< pattern)
      concl = egrep(string: banner, pattern: pattern, icase: TRUE);
    else
      concl = egrep(string: res, pattern: pattern, icase: FALSE);

    if (concl) {
      if (concluded)
        concluded += '\n';

      # nb: Minor formatting change for the reporting.
      concl = chomp(concl);
      concl = ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
      concluded += "  " + concl;

      # Existence of the banner is always counting as a successful detection.
      if ("^Server" >< pattern) {
        found += 2;
      } else {
        found++;
        if (!conclurl)
          conclurl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
      }
    }
  }

  if (found > 1) {

    version = "unknown";
    install = "/";

    # smhversion = "HP System Management Homepage v7.3.3.1";
    # smhversion = "HPE System Management Homepage v7.6.3.3";
    vers = eregmatch(pattern: 'smhversion = "HPE? System Management Homepage v([0-9.]+)', string: res);
    if (!isnull(vers[1])) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }

    if (version == "unknown") {
      # Server: CompaqHTTPServer/9.9 HPE System Management Homepage/7.6.3.3
      # Server: CompaqHTTPServer/9.9 HP System Management Homepage/6.2.0.13
      vers = eregmatch(pattern: "Server\s*:.+HPE? System Management Homepage/([0-9.]+)", string: res);
      if (!isnull(vers[1]))
        version = vers[1];
    }

    set_kb_item(name: "hp/smh/detected", value: TRUE);
    set_kb_item(name: "hp/smh/http/detected", value: TRUE);

    # nb: The latest CVE from 2016 still has the a:hp: CPE. To make this future proof / to be
    # prepared we're just using / registering a:hpe: additionally.
    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base:"cpe:/a:hp:system_management_homepage:");
    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base:"cpe:/a:hpe:system_management_homepage:");
    if (!cpe) {
      cpe = "cpe:/a:hp:system_management_homepage";
      cpe2 = "cpe:/a:hpe:system_management_homepage";
    }

    register_product(cpe: cpe, location: install, port: port, service: "www");
    register_product(cpe: cpe2, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "HP/HPE System Management Homepage (SMH)",
                                             version: version,
                                             install: install,
                                             cpe: cpe,
                                             concludedUrl: conclurl,
                                             concluded: concluded),
                port: port);
  }
}

exit(0);