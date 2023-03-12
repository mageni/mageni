# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2010.2115");
  script_cve_id("CVE-2009-4300", "CVE-2009-4304", "CVE-2010-1613", "CVE-2010-1614", "CVE-2010-1615", "CVE-2010-1616", "CVE-2010-1617", "CVE-2010-1618", "CVE-2010-1619", "CVE-2010-2228", "CVE-2010-2229", "CVE-2010-2230", "CVE-2010-2231");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("Debian: Security Advisory (DSA-2115)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB5");

  script_xref(name:"Advisory-ID", value:"DSA-2115");
  script_xref(name:"URL", value:"https://www.debian.org/security/2010/dsa-2115");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'moodle' package(s) announced via the DSA-2115 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several remote vulnerabilities have been discovered in Moodle, a course management system. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2010-1613

Moodle does not enable the Regenerate session id during login setting by default, which makes it easier for remote attackers to conduct session fixation attacks.

CVE-2010-1614

Multiple cross-site scripting (XSS) vulnerabilities allow remote attackers to inject arbitrary web script or HTML via vectors related to (1) the Login-As feature or (2) when the global search feature is enabled, unspecified global search forms in the Global Search Engine.

CVE-2010-1615

Multiple SQL injection vulnerabilities allow remote attackers to execute arbitrary SQL commands via vectors related to (1) the add_to_log function in mod/wiki/view.php in the wiki module, or (2) data validation in some forms elements related to lib/form/selectgroups.php.

CVE-2010-1616

Moodle can create new roles when restoring a course, which allows teachers to create new accounts even if they do not have the moodle/user:create capability.

CVE-2010-1617

user/view.php does not properly check a role, which allows remote authenticated users to obtain the full names of other users via the course profile page.

CVE-2010-1618

A Cross-site scripting (XSS) vulnerability in the phpCAS client library allows remote attackers to inject arbitrary web script or HTML via a crafted URL, which is not properly handled in an error message.

CVE-2010-1619

A Cross-site scripting (XSS) vulnerability in the fix_non_standard_entities function in the KSES HTML text cleaning library (weblib.php) allows remote attackers to inject arbitrary web script or HTML via crafted HTML entities.

CVE-2010-2228

A Cross-site scripting (XSS) vulnerability in the MNET access-control interface allows remote attackers to inject arbitrary web script or HTML via vectors involving extended characters in a username.

CVE-2010-2229

Multiple cross-site scripting (XSS) vulnerabilities in blog/index.php allow remote attackers to inject arbitrary web script or HTML via unspecified parameters.

CVE-2010-2230

The KSES text cleaning filter in lib/weblib.php does not properly handle vbscript URIs, which allows remote authenticated users to conduct cross-site scripting (XSS) attacks via HTML input.

CVE-2010-2231

A Cross-site request forgery (CSRF) vulnerability in report/overview/report.php in the quiz module allows remote attackers to hijack the authentication of arbitrary users for requests that delete quiz attempts via the attemptid parameter.

This security update switches to a new upstream version and requires database updates. After installing the fixed package, you must visit <http://localhost/moodle/admin/> and follow the update instructions.

For the stable distribution (lenny), these problems have been fixed in version ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'moodle' package(s) on Debian 5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB5") {

  if(!isnull(res = isdpkgvuln(pkg:"moodle", ver:"1.8.13-1", rls:"DEB5"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
