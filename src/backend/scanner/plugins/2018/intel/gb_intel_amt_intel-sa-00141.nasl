##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_intel_amt_intel-sa-00141.nasl 13032 2019-01-11 07:56:51Z mmartin $
#
# Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00141)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = 'cpe:/h:intel:active_management_technology';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141479");
  script_version("$Revision: 13032 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-11 08:56:51 +0100 (Fri, 11 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-09-14 14:46:25 +0700 (Fri, 14 Sep 2018)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2018-3616", "CVE-2018-3657", "CVE-2018-3658");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Intel Active Management Technology Multiple Vulnerabilities (INTEL-SA-00141)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_intel_amt_webui_detect.nasl");
  script_mandatory_keys("intel_amt/installed");

  script_tag(name:"summary", value:"Multiple potential security vulnerabilities in Intel Active Management
Technology (AMT) in Intel CSME firmware may allow arbitrary code execution, a partial denial of service or
information disclosure.");

  script_tag(name:"insight", value:"Intel Active Management Technology is prone to multiple vulnerabilities:

  - Bleichenbacher-style side channel vulnerability in TLS implementation may allow an unauthenticated user to
potentially obtain the TLS session key via the network. (CVE-2018-3616)

  - Multiple buffer overflows may allow a privileged user to potentially execute arbitrary code with Intel AMT
execution privilege via local access. (CVE-2018-3657)

  - Multiple memory leaks may allow an unauthenticated user to potentially cause a partial denial of service via
network access. (CVE-2018-3658)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Intel Active Management Technology before 12.0.5.");

  script_tag(name:"solution", value:"Upgrade to appropriate Intel CSME firmware version.");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00141.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "12.0.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
