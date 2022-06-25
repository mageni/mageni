# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.844361");
  script_version("2020-03-13T09:57:52+0000");
  script_cve_id("CVE-2019-20503", "CVE-2020-6805", "CVE-2020-6806", "CVE-2020-6807", "CVE-2020-6808", "CVE-2020-6810", "CVE-2020-6812", "CVE-2020-6813", "CVE-2020-6814", "CVE-2020-6815", "CVE-2020-6809", "CVE-2020-6811");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2020-03-13 11:42:45 +0000 (Fri, 13 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-12 04:00:13 +0000 (Thu, 12 Mar 2020)");
  script_name("Ubuntu: Security Advisory for firefox (USN-4299-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU19\.10|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-March/005355.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the USN-4299-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked in to opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, spoof the URL or
other browser chrome, obtain sensitive information, bypass Content
Security Policy (CSP) protections, or execute arbitrary code.
(CVE-2019-20503, CVE-2020-6805, CVE-2020-6806, CVE-2020-6807,
CVE-2020-6808, CVE-2020-6810, CVE-2020-6812, CVE-2020-6813, CVE-2020-6814,
CVE-2020-6815)

It was discovered that Web Extensions with the all-url permission could
access local files. If a user were tricked in to installing a specially
crafted extension, an attacker could potentially exploit this to obtain
sensitive information. (CVE-2020-6809)

It was discovered that the Devtools' 'Copy as cURL' feature did not fully
escape website-controlled data. If a user were tricked in to using the
'Copy as cURL' feature to copy and paste a command with specially crafted
data in to a terminal, an attacker could potentially exploit this to
execute arbitrary commands via command injection. (CVE-2020-6811)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

if(release == "UBUNTU19.10") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"74.0+build3-0ubuntu0.19.10.1", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"74.0+build3-0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"74.0+build3-0ubuntu0.16.04.1", rls:"UBUNTU16.04 LTS"))) {
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