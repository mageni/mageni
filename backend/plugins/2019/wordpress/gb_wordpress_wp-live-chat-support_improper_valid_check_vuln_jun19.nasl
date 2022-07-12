# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.112115");
  script_version("2019-06-14T12:02:13+0000");
  script_tag(name:"last_modification", value:"2019-06-14 12:02:13 +0000 (Fri, 14 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-14 12:51:12 +0200 (Fri, 14 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-12498");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Live Chat Support Plugin <= 8.0.32 Improper Authentication Validation Check Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Live Chat Support is prone to an improper
  validation check for authentication.");
  
  script_tag(name:"insight", value:"The flaw originates because of an improper validation check
  for authentication that apparently could allow unauthenticated users to access restricted REST API endpoints.");
  
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to:

  - steal the entire chat history for all chat sessions.

  - modify or delete the chat history.

  - inject messages into an active chat session, posing as a customer support agent.

  - forcefully end active chat sessions, as part of a denial of service (DoS) attack.");
  
  script_tag(name:"affected", value:"WordPress Live Chat Support plugin through version 8.0.32.");
  
  script_tag(name:"solution", value:"Update to version 8.0.33 or later.");

  script_xref(name:"URL", value:"https://thehackernews.com/2019/06/wordpress-live-chat-plugin.html");
  script_xref(name:"URL", value:"https://wordpress.org/plugins/wp-live-chat-support/#developers");

  exit(0);
}

CPE = "cpe:/a:wordpress:wordpress";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if(dir == "/")
  dir = "";

url = dir + "/wp-content/plugins/wp-live-chat-support/readme.txt";
res = http_get_cache(port: port, item: url);

if("=== WP Live Chat Support ===" >< res && "Changelog" >< res) {

  cl = eregmatch(pattern: "== Changelog ==.+", string: res);
  if(cl[0]) {

    vers = eregmatch(pattern: "= ([0-9.]+) (=|-|[0-9])", string: cl[0]);

    if(vers[1] && version_is_less(version: vers[1], test_version: "8.0.33")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "8.0.33", file_checked: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
