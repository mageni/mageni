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

CPE = "cpe:/a:my-netdata:netdata";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142518");
  script_version("2019-06-28T06:52:39+0000");
  script_tag(name:"last_modification", value:"2019-06-28 06:52:39 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-28 06:48:04 +0000 (Fri, 28 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-9834");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetData <= 1.13.0 HTML Injection Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_netdata_detect.nasl");
  script_mandatory_keys("netdata/detected");

  script_tag(name:"summary", value:"NetData is prone to an HTML injection vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Netdata web application allows remote attackers to inject their own
  malicious HTML code into an imported snapshot, aka HTML Injection.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker-supplied HTML to run in the context
  of the affected browser, potentially allowing the attacker to steal authentication credentials or to control how
  the site is rendered to the user.");

  script_tag(name:"affected", value:"NetData version 1.13.0 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 28th June, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/46545");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
location = infos['location'];

if (version_is_less_equal(version: version, test_version: "1.13.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
