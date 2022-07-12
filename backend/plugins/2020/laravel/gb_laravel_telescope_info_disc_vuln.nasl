# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:laravel:telescope";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112808");
  script_version("2020-08-13T09:55:14+0000");
  script_tag(name:"last_modification", value:"2020-08-14 09:58:14 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-12 10:54:11 +0000 (Wed, 12 Aug 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Laravel Telescope Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_laravel_detect.nasl");
  script_mandatory_keys("laravel/telescope/detected");

  script_tag(name:"summary", value:"Laravel Telescope is erroneously publicly accessible.");

  script_tag(name:"vuldetect", value:"Checks from previously collected information if
  Laravel Telescope is publicly accessible.");

  script_tag(name:"insight", value:"Laravel has publicly accessible instances of its Telescope software.
  This allows seeing detailed HTTP requests, including Cookies.");

  script_tag(name:"affected", value:"Laravel with public access to its Telescope software component.");

  script_tag(name:"solution", value:"Restrict public access to Laravel Telescope.");

  script_xref(name:"URL", value:"https://github.com/hannob/snallygaster/commit/e1ed99667bf5716673a9836acef5cd828e3cd07a");
  script_xref(name:"URL", value:"https://laravel.com/docs/master/telescope#dashboard-authorization");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

if(!port = get_app_port(cpe: CPE, service: "www"))
  exit(0);

if(!get_kb_item("laravel/telescope/" + port + "/detected"))
  exit(99);

if(!url = get_app_location(cpe: CPE, port: port))
  exit(0);

report = "Laravel Telescope is exposed to the public under the following URL: " + http_report_vuln_url(port: port, url: url, url_only: TRUE);
security_message(port: port, data: report);
exit(0);
