###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_apr17_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MediaWiki Multiple Vulnerabilities - April17 (Windows)
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

CPE = 'cpe:/a:mediawiki:mediawiki';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106884");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-20 10:54:15 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2017-0361", "CVE-2017-0362", "CVE-2017-0363", "CVE-2017-0364", "CVE-2017-0365",
"CVE-2017-0366", "CVE-2017-0367", "CVE-2017-0368", "CVE-2017-0369", "CVE-2017-0370", "CVE-2017-0372");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities - April17 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki is prone to multiple vulnerabilities:

  - API parameters may now be marked as 'sensitive' to keep their values out of the logs (CVE-2017-0361)

  - 'Mark all pages visited' on the watchlist now requires a CSRF token (CVE-2017-0362)

  - Special:UserLogin and Special:Search allow redirect to interwiki links. (CVE-2017-0363, CVE-2017-0364)

  - XSS in SearchHighlighter::highlightText() when $wgAdvancedSearchHighlighting is true (CVE-2017-0365)

  - SVG filter evasion using default attribute values in DTD declaration (CVE-2017-0366)

  - LocalisationCache will no longer use the temporary directory in its fallback chain when trying to work out
where to write the cache (CVE-2017-0367)

  - Escape content model/format url parameter in message (CVE-2017-0368)

  - Sysops can undelete pages, although the page is protected against it (CVE-2017-0369)

  - Spam blacklist ineffective on encoded URLs inside file inclusion syntax's link parameter (CVE-2017-0370)

  - Parameters injection in SyntaxHighlight results in multiple vulnerabilities (CVE-2017-0372)");

  script_tag(name:"solution", value:"Upgrade to version 1.23.16, 1.27.3, 1.28.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-April/000207.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-April/000209.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.23.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.23.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.26.0", test_version2: "1.27.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.28.0", test_version2: "1.28.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
