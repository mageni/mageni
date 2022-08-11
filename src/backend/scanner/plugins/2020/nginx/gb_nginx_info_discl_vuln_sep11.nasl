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
  script_oid("1.3.6.1.4.1.25623.1.0.117011");
  script_version("2020-11-05T14:05:29+0000");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-05 13:55:27 +0000 (Thu, 05 Nov 2020)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2011-4968");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("nginx Information Disclosure Vulnerability (CVE-2011-4968)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("nginx_detect.nasl");
  script_mandatory_keys("nginx/installed");

  script_tag(name:"summary", value:"nginx is prone to an information disclosure vulnerability in
  the http proxy module.");

  script_tag(name:"insight", value:"nginx http proxy module does not verify peer identity of https
  origin server which could facilitate man-in-the-middle attack (MITM).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"nginx versions before 1.7.0.");

  script_tag(name:"solution", value:"Update to version 1.7.0 and enable the 'proxy_ssl_verify'
  option in the nginx configuration if the http proxy module is used.");

  script_xref(name:"URL", value:"https://nginx.org/en/CHANGES");
  script_xref(name:"URL", value:"https://trac.nginx.org/nginx/ticket/13");
  script_xref(name:"URL", value:"https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_verify");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.7.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
