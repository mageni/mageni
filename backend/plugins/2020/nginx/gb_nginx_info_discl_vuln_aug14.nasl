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

CPE = "cpe:/a:nginx:nginx";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117010");
  script_version("2020-11-05T14:05:29+0000");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-05 13:50:27 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2014-3556");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx Information Disclosure Vulnerability (CVE-2014-3556)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");

  script_tag(name:"summary", value:"nginx is prone to an information disclosure vulnerability in
  the SMTP proxy.");

  script_tag(name:"insight", value:"A bug in nginx SMTP proxy was found, which allows an attacker in a
  privileged network position to inject commands into SSL sessions started with the STARTTLS command,
  potentially making it possible to steal sensitive information sent by clients.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nginx versions 1.5.6 - 1.7.3.");

  script_tag(name:"solution", value:"Update to version 1.6.1, 1.7.4 or later.");

  script_xref(name:"URL", value:"https://nginx.org/en/CHANGES");
  script_xref(name:"URL", value:"https://mailman.nginx.org/pipermail/nginx-announce/2014/000144.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.5.6", test_version2: "1.6.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.6.1 / 1.7.4");
  security_message(port: port, data: report);
  exit(0);
}

else if (version_in_range(version: version, test_version: "1.7.0", test_version2: "1.7.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.4");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
