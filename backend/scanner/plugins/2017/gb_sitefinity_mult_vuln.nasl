##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sitefinity_mult_vuln.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Sitefinity CMS Multiple Vulnerabilities
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

CPE = 'cpe:/a:progress:sitefinity';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140541");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-28 08:24:34 +0700 (Tue, 28 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Sitefinity CMS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sitefinity_detect.nasl");
  script_mandatory_keys("sitefinity/detected");

  script_tag(name:"summary", value:"Sitefinity CMS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Sitefinity CMS is prone to multiple vulnerabilities:

  - Broken Access Control: By using an unprotected function, a low privileged user can extract another user's
information such as email addresses, user ID, etc.

  - LINQ Injection: The identified LINQ injection enables an authenticated user to read sensitive data from the
database. Specifically, an attacker can query the password or its hash character by character. Depending on the
version of LINQ assembly in use, remote code execution could be possible as well.");

  script_tag(name:"affected", value:"Sitefinity before version 10.1.6527.0.");

  script_tag(name:"solution", value:"Update to version 10.1.6527.0 or later.");

  script_xref(name:"URL", value:"https://www.sec-consult.com/en/blog/advisories/broken-access-control-linq-injection-in-progress-sitefinity/index.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "10.1.6527.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.1.6527.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
