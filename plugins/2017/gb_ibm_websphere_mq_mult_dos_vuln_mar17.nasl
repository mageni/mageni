###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_mult_dos_vuln_mar17.nasl 12552 2018-11-28 04:39:18Z ckuersteiner $
#
# IBM WebSphere MQ Multiple Denial of Service Vulnerabilities - Mar17
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:ibm:websphere_mq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810800");
  script_version("$Revision: 12552 $");
  script_cve_id("CVE-2016-8971", "CVE-2016-8986");
  script_bugtraq_id(96412);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 05:39:18 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-13 16:01:06 +0530 (Mon, 13 Mar 2017)");

  script_name("IBM WebSphere MQ Multiple Denial of Service Vulnerabilities - Mar17");

  script_tag(name:"summary", value:"This host is installed with IBM WebSphere MQ
  and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An administration command can cause IBM WebSphere MQ to access an invalid
    memory address, leading to a segmentation failure and causing the queue manager
    to become unresponsive.

  - An improper validation of invalid HTTP requests.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  authenticated user with queue manager permissions to cause a segmentation fault
  which would result in the box having to be rebooted to resume normal operations.");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 8.0.0.0 through 8.0.0.5");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 8.0.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998663");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21998648");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

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

if(version_in_range(version:version, test_version:"8.0.0.0", test_version2:"8.0.0.5")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.0.0.6", install_path: path);
  security_message(port: port, data:report);
  exit(0);
}

exit(99);
