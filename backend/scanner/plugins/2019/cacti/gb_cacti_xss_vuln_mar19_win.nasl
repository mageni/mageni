# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112562");
  script_version("2019-04-25T11:36:15+0000");
  script_tag(name:"last_modification", value:"2019-04-25 11:36:15 +0000 (Thu, 25 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-10 12:04:40 +0200 (Wed, 10 Apr 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");

  script_cve_id("CVE-2019-11025");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.2.3 XSS Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Cacti is prone to a cross-site scripting (XSS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"No escaping occurs in clearFilter() in utilities.php before printing
  out the value of the SNMP community string (SNMP Options) in the View poller cache, which leads to XSS.");
  script_tag(name:"affected", value:"Cacti prior to version 1.2.3.");
  script_tag(name:"solution", value:"Update to version 1.2.3 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/2581");

  exit(0);
}

CPE = 'cpe:/a:cacti:cacti';

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
path = infos["location"];

if(version_is_less(version: version, test_version: "1.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
