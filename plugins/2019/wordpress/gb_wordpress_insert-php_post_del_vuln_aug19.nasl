# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions excerpted from a referenced source are
# Copyright (C) of the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.112625");
  script_version("2019-08-14T11:53:22+0000");
  script_tag(name:"last_modification", value:"2019-08-14 11:53:22 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 11:45:00 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-14773");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("WordPress Woody Ad Snippets Plugin < 2.2.6 File Deletion Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");

  script_tag(name:"summary", value:"The Wordpress plugin Woody Ad Snippets is prone to a file deletion vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability would allow a remote attacker
  to delete a WordPress post.

  Posts in this context refers not just to blog posts, but to anything stored as a post,
  which includes pages and various data from plugins, like the snippet for this plugin.");

  script_tag(name:"affected", value:"WordPress Woody Ad Snippets plugin before version 2.2.6.");

  script_tag(name:"solution", value:"Update to version 2.2.6 or later.");

  script_xref(name:"URL", value:"https://wordpress.org/plugins/insert-php/#developers");
  script_xref(name:"URL", value:"https://www.pluginvulnerabilities.com/2019/08/01/post-deletion-vulnerability-in-woody-ad-snippets/");

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

url = dir + "/wp-content/plugins/insert-php/readme.txt";
res = http_get_cache(port: port, item: url);

if(("Insert PHP" >< res || "Woody ad snippets" >< res) && "Changelog" >< res) {
  cl = eregmatch(pattern: "== Changelog ==.*", string: res);

  if(cl[0]) {
    vers = eregmatch(pattern:"= ([0-9.]+) =", string:cl[0]);

    if(vers[1] && version_is_less(version: vers[1], test_version: "2.2.6")) {
      report = report_fixed_ver(installed_version: vers[1], fixed_version: "2.2.6", file_checked: url);
      security_message(port: port, data: report);
      exit(0);
    }
  }
}

exit(99);
