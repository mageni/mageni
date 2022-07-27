# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:open-emr:openemr";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.142236");
  script_version("2019-04-10T13:44:10+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:44:10 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-09 14:19:47 +0000 (Tue, 09 Apr 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2018-18035");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 5.0.1 Patch 6 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"A vulnerability in flashcanvas.swf in OpenEMR could allow an unauthenticated,
  remote attacker to conduct a cross-site scripting (XSS) attack on a targeted system.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"OpenEMR prior to version 5.0.1 Patch 6.");

  script_tag(name:"solution", value:"Update to version 5.0.1 Patch 6 or later.");

  script_xref(name:"URL", value:"https://www.open-emr.org/wiki/index.php/OpenEMR_Patches");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "5.0.1-6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.1-6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
