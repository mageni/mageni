###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_domino_info_disc_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# IBM Domino TLS Server Diffie-Hellman Key Validation Vulnerability
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

CPE = "cpe:/a:ibm:lotus_domino";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106873");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-15 11:51:23 +0700 (Thu, 15 Jun 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-6087");
  script_bugtraq_id(98794);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM Domino TLS Server Diffie-Hellman Key Validation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_lotus_domino_detect.nasl");
  script_mandatory_keys("Domino/Version");

  script_tag(name:"summary", value:"A vulnerability in the IBM Domino TLS server's Diffie-Hellman parameter
validation could potentially be exploited in a small subgroup attack which could result in a less secure
connection. An attacker may be able to exploit this vulnerability to obtain user authentication credentials.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"IBM Domino 8.5.1, 8.5.2, 8.5.3, 9.0 and 9.0.1.");

  script_tag(name:"solution", value:"Update to version 9.0.1 FP8.");

  script_xref(name:"URL", value:"https://www-01.ibm.com/support/docview.wss?uid=swg22002808");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc"); # Used in get_highest_app_version
include("host_details.inc");

if (!version = get_highest_app_version(cpe: CPE))
  exit(0);

checkvers = ereg_replace(string: version, pattern: "FP", replace: ".");

if (version_is_greater_equal(version: checkvers, test_version: "8.5.1") &&
    version_is_less(version:checkvers, test_version: "9.0.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.0.1 FP8");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);
