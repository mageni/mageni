###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_osnexus_quantastor_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# OSNEXUS QuantaStor Multiple Vulnerabilities
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

CPE = "cpe:/a:osnexus:quantastor";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140333");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-29 13:36:20 +0700 (Tue, 29 Aug 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2017-9978", "CVE-2017-9979");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OSNEXUS QuantaStor Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_osnexus_quantastor_detect.nasl");
  script_mandatory_keys("osnexus_quantastor/detected");

  script_tag(name:"summary", value:"OSNEXUS QuantaStor is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"OSNEXUS QuantaStor is prone to multiple vulnerabilities:

  - A flaw was found with the error message sent as a response for users that don't exist on the system. An
attacker could leverage this information to fine-tune and enumerate valid accounts on the system by searching for
common usernames. (CVE-2017-9978)

  - If the REST call invoked does not exist, an error will be triggered containing the invalid method previously
invoked. The response sent to the user isn't sanitized in this case. An attacker can leverage this issue by
including arbitrary HTML or JavaScript code as a parameter, aka XSS. (CVE-2017-9979)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"OSNEXUS QuantaStor prior to version 4.3.1.007");

  script_tag(name:"solution", value:"Update to version 4.3.1.007 or later.");

  script_xref(name:"URL", value:"http://www.vvvsecurity.com/advisories/vvvsecurity-advisory-2017-6943.txt");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "4.3.1.007")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.3.1.007");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
