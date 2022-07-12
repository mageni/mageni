# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/a:stefan_ritt:elog_web_logbook";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143636");
  script_version("2020-03-25T07:44:05+0000");
  script_tag(name:"last_modification", value:"2020-03-25 11:04:45 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-25 07:31:41 +0000 (Wed, 25 Mar 2020)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2020-8859");

  script_name("ELOG < 3.1.4-033e292 DoS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_elog_detect.nasl");
  script_mandatory_keys("ELOG/detected");

  script_tag(name:"summary", value:"ELOG is prone to a denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This vulnerability allows remote attackers to create a denial-of-service
  condition on affected installations of ELOG Electronic Logbook. Authentication is not required to exploit this
  vulnerability. The specific flaw exists within the processing of HTTP parameters. A crafted request can trigger
  the dereference of a null pointer.");

  script_tag(name:"impact", value:"An attacker can leverage this vulnerability to create a denial-of-service condition.");

  script_tag(name:"affected", value:"ELOG prior version 3.1.4-033e292.");

  script_tag(name:"solution", value:"Update to version 3.1.4-033e292 or later.");

  script_xref(name:"URL", value:"https://elog.psi.ch/elogs/Forum/69114");
  script_xref(name:"URL", value:"https://www.zerodayinitiative.com/advisories/ZDI-20-252/");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (revcomp(a: version, b: "3.1.4.033e292") < 0) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.4-033e292", install_path: location);
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
