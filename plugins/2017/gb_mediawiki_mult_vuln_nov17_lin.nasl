###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_nov17_lin.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MediaWiki Multiple Vulnerabilities - November17 (Linux)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

CPE = 'cpe:/a:mediawiki:mediawiki';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112124");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-11-16 11:18:15 +0100 (Thu, 16 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2017-8808", "CVE-2017-8809", "CVE-2017-8810", "CVE-2017-8811", "CVE-2017-8812", "CVE-2017-8814", "CVE-2017-8815");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities - November17 (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki is prone to multiple vulnerabilities:

  - XSS when the $wgShowExceptionDetails setting is false and the browser sends non-standard URL escaping. (CVE-2017-8808)

  - A Reflected File Download vulnerability in api.php. (CVE-2017-8809)

  - When a private wiki is configured, it provides different error messages for failed login attempts - depending on whether the username exists -
which allows remote attackers to enumerate account names and conduct brute-force attacks via a series of requests. (CVE-2017-8810)

  - The implementation of raw message parameter expansion allows HTML mangling attacks. (CVE-2017-8811)

  - Allowing remote attackers to inject > (greater than) characters via the id attribute of a headline. (CVE-2017-8812)

  - The language converter allows attackers to replace text inside tags via a rule definition followed by 'a lot of junk'. (CVE-2017-8814)

  - The language converter allows attribute injection attacks via glossary rules. (CVE-2017-8815)");

  script_tag(name:"solution", value:"Upgrade to version 1.27.4, 1.28.3, 1.29.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-November/000216.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.27.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.4");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.28.0", test_version2: "1.28.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.29.0", test_version2: "1.29.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.29.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
