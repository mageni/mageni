###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_mult_vuln_feb17.nasl 12552 2018-11-28 04:39:18Z ckuersteiner $
#
# IBM WebSphere MQ Multiple Vulnerabilities - February17
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
  script_oid("1.3.6.1.4.1.25623.1.0.106620");
  script_version("$Revision: 12552 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 05:39:18 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-02-27 13:28:29 +0700 (Mon, 27 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-3013", "CVE-2016-3052", "CVE-2016-8915", "CVE-2016-9009");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere MQ Multiple Vulnerabilities - February17");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"IBM WebSphere MQ is prone to multiple vulnerabilities:

  - MQ Channel data conversion denial of service (CVE-2016-3013)

  - Java clients might send a password in clear text (CVE-2016-3052)

  - Invalid channel protocol flows cause denial of service on HP-UX (CVE-2016-8915)

  - Cluster channel definition causes denial of service to cluster (CVE-2016-9009)");

  script_tag(name:"affected", value:"IBM WebSphere MQ 8");

  script_tag(name:"solution", value:"Upgrade to version 8.0.0.6.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998661');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998660');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998649');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998647');

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

if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
