###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_http_dir_trav.nasl 12019 2018-10-22 14:05:34Z cfischer $
#
# Generic HTTP Directory Traversal
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106756");
  script_version("$Revision: 12019 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 16:05:34 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-18 14:50:27 +0200 (Tue, 18 Apr 2017)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Generic HTTP Directory Traversal");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 443, 8443, 81, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP requests and checks the response.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

traversal = make_list("",
                      crap(data: "../", length: 3*6),
                      crap(data: ".../", length: 4*6),
                      crap(data: "%2e%2e%2f", length: 9*6),
                      crap(data: "%2e%2e/", length: 6*6),
                      crap(data: "..%2f", length: 5*6),
                      crap(data: "..\", length: 3*6),
                      crap(data: "...\", length: 4*6),
                      crap(data: "%2e%2e%5c", length: 9*6),
                      crap(data: "%2e%2e\", length: 7*6),
                      crap(data: "..%5c", length: 5*6),
                      crap(data: "..%255c", length: 7*6),
                      crap(data: "%c0%ae%c0%ae/", length: 13*6), # nb: JVM UTF-8 bug for various products, see e.g. 2011/gb_trend_micro_data_loss_prevention_48225.nasl or 2018/apache/gb_apache_tomcat_30633.nasl
                      crap(data: "%252e%252e%255c", length: 15*6));

files = traversal_files();

foreach trav (traversal) {
  foreach file (keys(files)) {
    url = "/" + trav + files[file];
    req = http_get(port: port, item: url);
    #nb: Don't use http_keepalive_send_recv() here as embedded devices
    #which are often vulnerable shows issues when requesting a keepalive connection.
    res = http_send_recv(port: port, data: req);

    if (egrep(pattern: file, string: res)) {
      vuln += report_vuln_url(port: port, url: url) + "\n\n";
      vuln += "Request:\n" + req +"\nResponse:\n" + res + "\n\n\n";
    }
  }
}

if (vuln) {
  report = "The following traversal URL(s) where found:\n\n" + vuln;
  security_message(port: port, data: report);
}

exit(0);