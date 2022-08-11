##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_bigfix_remote_control_mult_vuln1.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# IBM Endpoint Manager for Remote Control Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:ibm:bigfix_remote_control';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106435");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-12-07 11:10:46 +0700 (Wed, 07 Dec 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2015-1915");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Endpoint Manager for Remote Control Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_bigfix_remote_control_detect.nasl");
  script_mandatory_keys("ibm/bigfix_remote_control/installed");

  script_tag(name:"summary", value:"IBM Endpoint Manager for Remote Control is prone to multiple
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"IBM Endpoint Manager for Remote Control is prone to multiple
vulnerabilities:

  - Multiple Java vulnerabilities

  - Multiple OpenSSL vulnerabilities

  - Encrypted session (SSL) cookie issue (CVE-2015-1915)");

  script_tag(name:"impact", value:"An attacker may obtain sensitive information.");

  script_tag(name:"affected", value:"Version 9.1.0 and 9.0.1.");

  script_tag(name:"solution", value:"Install Interim Fix 9.1.0-TIV-IEMRC910-IF0006 or upgrade to a later
version.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg21882571");
  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg24039331");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_greater(version: version, test_version: "9.0.1") &&
    version_is_less(version: version, test_version: "9.1.0.0605")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.0.0605");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
