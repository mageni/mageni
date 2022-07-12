###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mediawiki_mult_vuln_aug16_win.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# MediaWiki Multiple Vulnerabilities - Aug16 (Windows)
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
  script_oid("1.3.6.1.4.1.25623.1.0.106784");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-21 11:45:55 +0200 (Fri, 21 Apr 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_cve_id("CVE-2016-6331", "CVE-2016-6332", "CVE-2016-6333", "CVE-2016-6334", "CVE-2016-6335",
"CVE-2016-6336", "CVE-2016-6337");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities - Aug16 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_mediawiki_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"MediaWiki is prone to multiple vulnerabilities:

  - ApiParse allows remote attackers to bypass intended per-title read restrictions via a parse action to api.php.
(CVE-2016-6331)

  - Remote attackers may obtain sensitive information by leveraging failure to terminate sessions when a user
account is blocked and when $wgBlockDisablesLogin is true. (CVE-2016-6332)

  - Cross-site scripting (XSS) vulnerability in the CSS user subpage preview feature allows remote attackers to
inject arbitrary web script or HTML via the edit box in Special:MyPage/common.css. (CVE-2016-6333)

  - Cross-site scripting (XSS) vulnerability in the Parser::replaceInternalLinks2 method allows remote attackers to
inject arbitrary web script or HTML via vectors involving replacement of percent encoding in unclosed internal
links. (CVE-2016-6334)

  - MediaWiki does not generate head items in the context of a given title, which allows remote attackers to obtain
sensitive information via a parse action to api.php. (CVE-2016-6335)

  - Remote authenticated users with undelete permissions may bypass intended suppressrevision and deleterevision
restrictions and remove the revision deletion status of arbitrary file revisions by using Special:Undelete.
(CVE-2016-6336)

  - Remote attackers may bypass intended session access restrictions by leveraging a call to the UserGetRights
function after Session::getAllowedUserRights. (CVE-2016-6337)");

  script_tag(name:"affected", value:"MediaWiki before 1.23.15, 1.26.x before 1.26.4, and 1.27.x before 1.27.1");

  script_tag(name:"solution", value:"Upgrade to version 1.23.15, 1.26.4, 1.27.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2016-August/000195.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.23.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.23.15");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.26.0", test_version2: "1.26.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.26.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "1.27.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
