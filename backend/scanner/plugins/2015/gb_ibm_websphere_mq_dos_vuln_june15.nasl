###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mq_dos_vuln_june15.nasl 12552 2018-11-28 04:39:18Z ckuersteiner $
#
# IBM WebSphere MQ 'PCF Response Message Handling' DoS Vulnerability - June 2015
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805580");
  script_version("$Revision: 12552 $");
  script_cve_id("CVE-2014-4771");
  script_bugtraq_id(74326);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-28 05:39:18 +0100 (Wed, 28 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-06-04 13:10:30 +0530 (Thu, 04 Jun 2015)");

  script_name("IBM WebSphere MQ 'PCF Response Message Handling' DoS Vulnerability - June 2015");

  script_tag(name:"summary", value:"This host is installed with IBM WebSphere MQ
  and is prone to denial-of-service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an unspecified error
  that is triggered when handling PCF response messages.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 7.0.1 before
  7.0.1.13, 7.1 before 7.1.0.6, 7.5 before 7.5.0.5 and 8 before 8.0.0.1");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 7.0.1.13
  or 7.1.0.6 or 7.5.0.5 or 8.0.0.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21696120");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
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

if(version_in_range(version:version, test_version:"7.0.1", test_version2:"7.0.1.12")) {
  fix = "7.0.1.13";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"7.1", test_version2:"7.1.0.5")) {
  fix = "7.1.0.6";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"7.5", test_version2:"7.5.0.4")) {
  fix = "7.5.0.5";
  VULN = TRUE;
}

if(version_in_range(version:version, test_version:"8.0", test_version2:"8.0.0.0")) {
  fix = "8.0.0.1";
  VULN = TRUE;
}

if(VULN) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
