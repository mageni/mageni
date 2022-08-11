###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_mult_dos_vuln_jul17.nasl 12552 2018-11-28 04:39:18Z ckuersteiner $
#
# IBM WebSphere MQ Multiple Denial of Service Vulnerabilities - Jul17
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:ibm:websphere_mq';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140259");
  script_version("$Revision: 12552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 05:39:18 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-08-01 09:50:24 +0700 (Tue, 01 Aug 2017)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");

  script_cve_id("CVE-2017-1236", "CVE-2017-1285");
  script_bugtraq_id(99505, 99538);

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere MQ Multiple Denial of Service Vulnerabilities - Jul17");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"IBM WebSphere MQ is prone to multiple vulnerabilities:

  - IBM WebSphere MQ could allow an authenticated user to potentially cause a denial of service by saving an
incorrect channel status inquiry. (CVE-2017-1236)

  - IBM WebSphere MQ could allow an authenticated user with authority to send a specially crafted message that
would cause a channel to remain in a running state but not process messages. (CVE-2017-1285)");

  script_tag(name:"affected", value:"IBM WebSphere MQ versions 9.0.1 and 9.0.2");

  script_tag(name:"solution", value:"Upgrade to version 9.0.3 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg22003510');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg22003856');

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

if (version_in_range(version: version, test_version: "9.0.1", test_version2: "9.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.3", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
