# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4122.2");
  script_cve_id("CVE-2019-11734", "CVE-2019-11735", "CVE-2019-11737", "CVE-2019-11738", "CVE-2019-11740", "CVE-2019-11741", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11747", "CVE-2019-11748", "CVE-2019-11749", "CVE-2019-11750", "CVE-2019-11752", "CVE-2019-5849", "CVE-2019-9812");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-04 18:15:00 +0000 (Fri, 04 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-4122-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS|19\.04)");

  script_xref(name:"Advisory-ID", value:"USN-4122-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4122-2");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1847354");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-4122-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4122-1 fixed vulnerabilities in Firefox. The update caused a
regression that resulted in a crash when changing YouTube playback speed
in some circumstances. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked in to opening a specially crafted website, an attacker could
 potentially exploit these to obtain sensitive information, bypass Content
 Security Policy (CSP) protections, bypass same-origin restrictions,
 conduct cross-site scripting (XSS) attacks, cause a denial of service, or
 execute arbitrary code. (CVE-2019-5849, CVE-2019-11734, CVE-2019-11735,
 CVE-2019-11737, CVE-2019-11738, CVE-2019-11740, CVE-2019-11742,
 CVE-2019-11743, CVE-2019-11744, CVE-2019-11746, CVE-2019-11748,
 CVE-2019-11749, CVE-2019-11750, CVE-2019-11752)

 It was discovered that a compromised content process could log in to a
 malicious Firefox Sync account. An attacker could potentially exploit
 this, in combination with another vulnerability, to disable the sandbox.
 (CVE-2019-9812)

 It was discovered that addons.mozilla.org and accounts.firefox.com could
 be loaded in to the same content process. An attacker could potentially
 exploit this, in combination with another vulnerability that allowed a
 cross-site scripting (XSS) attack, to modify browser settings.
 (CVE-2019-11741)

 It was discovered that the 'Forget about this site' feature in the history
 pane removes HTTP Strict Transport Security (HSTS) settings for sites on
 the pre-load list. An attacker could potentially exploit this to bypass
 the protections offered by HSTS. (CVE-2019-11747)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 16.04, Ubuntu 18.04, Ubuntu 19.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"69.0.2+build1-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"69.0.2+build1-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU19.04") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"69.0.2+build1-0ubuntu0.19.04.1", rls:"UBUNTU19.04"))) {
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
