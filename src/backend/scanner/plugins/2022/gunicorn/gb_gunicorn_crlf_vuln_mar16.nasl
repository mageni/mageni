# Copyright (C) 2022 Greenbone Networks GmbH
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

CPE = "cpe:/a:gunicorn:gunicorn";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.149044");
  script_version("2022-12-23T08:37:10+0000");
  script_tag(name:"last_modification", value:"2022-12-23 08:37:10 +0000 (Fri, 23 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-22 05:31:56 +0000 (Thu, 22 Dec 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-19 22:15:00 +0000 (Wed, 19 Jun 2019)");

  script_cve_id("CVE-2018-1000164");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Gunicorn <= 19.4.5 HTTP Response Splitting Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_gunicorn_http_detect.nasl");
  script_mandatory_keys("gunicorn/detected");

  script_tag(name:"summary", value:"Gunicorn is prone to a HTTP response splitting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Gunicorn contains an improper neutralization of crlf sequences
  in HTTP headers vulnerability in 'process_headers' function in 'gunicorn/http/wsgi.py' that can
  result in an attacker causing the server to return arbitrary HTTP headers.");

  script_tag(name:"affected", value:"Gunicorn version 19.4.5 and probably prior.");

  script_tag(name:"solution", value:"Update to version 19.5.0 or later.");

  script_xref(name:"URL", value:"https://github.com/benoitc/gunicorn/issues/1227");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less_equal(version: version, test_version: "19.4.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "19.5.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
