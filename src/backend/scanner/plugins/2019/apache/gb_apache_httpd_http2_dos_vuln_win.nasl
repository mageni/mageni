##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_httpd_http2_dos_vuln_win.nasl 13547 2019-02-08 15:53:13Z cfischer $
#
# Apache HTTP Server < 2.4.38 HTTP/2 DoS Vulnerability (Windows)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2019 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:apache:http_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141965");
  script_version("$Revision: 13547 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-08 16:53:13 +0100 (Fri, 08 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-02-05 13:39:00 +0700 (Tue, 05 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2018-17189");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache HTTP Server < 2.4.38 HTTP/2 DoS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("apache/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"By sending request bodies in a slow loris way to plain resources, the h2
stream for that request unnecessarily occupied a server thread cleaning up that incoming data. This affects only
HTTP/2 connections. A possible mitigation is to not enable the h2 protocol.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Apache HTTP server version 2.4.37 and prior.");

  script_tag(name:"solution", value:"Update to version 2.4.38 or later.");

  script_xref(name:"URL", value:"https://httpd.apache.org/security/vulnerabilities_24.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

affected = make_list('2.4.37',
                     '2.4.35',
                     '2.4.34',
                     '2.4.33',
                     '2.4.30',
                     '2.4.29',
                     '2.4.28',
                     '2.4.27',
                     '2.4.26',
                     '2.4.25',
                     '2.4.23',
                     '2.4.20',
                     '2.4.18',
                     '2.4.17' );

foreach af (affected) {
  if (version == af) {
    report = report_fixed_ver(installed_version: version, fixed_version: "2.4.38");
    security_message(port: 0, data: report);
    exit(0);
  }
}

exit(99);