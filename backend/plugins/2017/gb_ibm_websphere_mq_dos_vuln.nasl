###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_dos_vuln.nasl 12576 2018-11-29 10:48:52Z cfischer $
#
# IBM WebSphere MQ Denial of Service Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
###############################################################################

CPE = 'cpe:/a:ibm:websphere_mq';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106909");
  script_version("$Revision: 12576 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-29 11:48:52 +0100 (Thu, 29 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-06-27 12:09:42 +0700 (Tue, 27 Jun 2017)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2017-1117");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere MQ Denial of Service Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_detect.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ could allow an authenticated user to cause a denial of
service to the MQXR channel when trace is enabled.");

  script_tag(name:"affected", value:"IBM WebSphere MQ versions 8.0.0.0 - 8.0.0.5, 9.0.1 and 9.0.0.0");

  script_tag(name:"solution", value:"Upgrade to version 8.0.0.6, 9.0.0.1, 9.0.2 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg22001468');

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.2", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "9.0.0.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.0.1", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
