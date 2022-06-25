##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_rsa_archer_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# RSA Archer Multiple Vulnerabilities
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

CPE = "cpe:/a:emc:rsa_archer_grc";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106919");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-07-03 16:15:11 +0700 (Mon, 03 Jul 2017)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-4998", "CVE-2017-4999", "CVE-2017-5000", "CVE-2017-5001", "CVE-2017-5002");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("RSA Archer Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_rsa_archer_detect.nasl");
  script_mandatory_keys("rsa_archer/installed");

  script_tag(name:"summary", value:"RSA Archer is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"RSA Archer is prone to multiple vulnerabilities:

  - Cross-Site Request Forgery Vulnerability (CVE-2017-4998)

  - Authorization Bypass Through User-Controlled Key Vulnerability (CVE-2017-4999)

  - Information Disclosure Vulnerability (CVE-2017-5000)

  - Cross Site Scripting Vulnerability (CVE-2017-5001)

  - Open Redirect Vulnerability (CVE-2017-5002)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to RSA Archer GRC 6.2.0.2 or later.");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Jun/49");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "6.2.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.2.0.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
