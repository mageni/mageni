# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.844052");
  script_version("2019-06-20T06:01:12+0000");
  script_cve_id("CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11695", "CVE-2019-11696", "CVE-2019-11699", "CVE-2019-11701", "CVE-2019-7317", "CVE-2019-9800", "CVE-2019-9814", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820", "CVE-2019-9821", "CVE-2019-11697", "CVE-2019-11698", "CVE-2019-9816");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-06-20 06:01:12 +0000 (Thu, 20 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-15 02:00:31 +0000 (Sat, 15 Jun 2019)");
  script_name("Ubuntu Update for firefox USN-3991-3");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.10|UBUNTU19\.04|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004959.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the USN-3991-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3991-1 fixed vulnerabilities in Firefox, and USN-3991-2 fixed a
subsequent regression. The update caused an additional regression that
resulted in Firefox failing to load correctly after executing it in safe
mode. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, spoof the browser
 UI, trick the user in to launching local executable binaries, obtain
 sensitive information, conduct cross-site scripting (XSS) attacks, or
 execute arbitrary code. (CVE-2019-11691, CVE-2019-11692, CVE-2019-11693,
 CVE-2019-11695, CVE-2019-11696, CVE-2019-11699, CVE-2019-11701,
 CVE-2019-7317, CVE-2019-9800, CVE-2019-9814, CVE-2019-9817, CVE-2019-9819,
 CVE-2019-9820, CVE-2019-9821)
 
 It was discovered that pressing certain key combinations could bypass
 addon installation prompt delays. If a user opened a specially crafted
 website, an attacker could potentially exploit this to trick them in to
 installing a malicious extension. (CVE-2019-11697)
 
 It was discovered that history data could be exposed via drag and drop
 of hyperlinks to and from bookmarks. If a user were tricked in to dragging
 a specially crafted hyperlink to the bookmark toolbar or sidebar, and
 subsequently back in to the web content area, an attacker could
 potentially exploit this to obtain sensitive information. (CVE-2019-11698)
 
 A type confusion bug was discovered with object groups and UnboxedObjects.
 If a user were tricked in to opening a specially crafted website after
 enabling the UnboxedObjects feature, an attacker could potentially
 exploit this to bypass security checks. (CVE-2019-9816)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0.2+build2-0ubuntu0.18.10.1", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0.2+build2-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0.2+build2-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"67.0.2+build2-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
