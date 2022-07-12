# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:tableausoftware:tableau_server";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114163");
  script_version("2019-12-16T09:50:28+0000");
  script_tag(name:"last_modification", value:"2019-12-16 09:50:28 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-13 16:06:07 +0100 (Fri, 13 Dec 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-19719");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Tableau Server XSS Vulnerability (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("sw_tableau_server_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("tableau_server/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Tableau server is prone to a cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"Tableau Server on Windows and Linux allows XSS via the embeddedAuthRedirect page.
  The server fails to properly validate the path that is presented on this redirect page.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to initiate a reflected
  cross-site scripting operation via JavaScript, which runs in the client context. Alternatively, a Tableau server
  user who clicks on a malicious link could be redirected to an attacker-controlled location.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Tableau server version 10.3 through 2019.4.");

  script_tag(name:"solution", value:"Update to version 2019.1.10, 2019.2.6, 2019.3.2 or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_in_range(version: version, test_version: "2019.1", test_version2: "2019.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2019.1.10");
}
else if(version_in_range(version: version, test_version: "2019.2", test_version2: "2019.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2019.2.6");
}
else if(version_in_range(version: version, test_version: "10.3", test_version2: "2019.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Fix coming in future release");
}

if(report) {
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
