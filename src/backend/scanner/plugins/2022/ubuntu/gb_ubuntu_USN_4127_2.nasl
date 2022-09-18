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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4127.2");
  script_cve_id("CVE-2018-20406", "CVE-2018-20852", "CVE-2019-10160", "CVE-2019-5010", "CVE-2019-9636", "CVE-2019-9740", "CVE-2019-9947", "CVE-2019-9948");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-05 18:53:00 +0000 (Tue, 05 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-4127-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(12\.04\ LTS|14\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-4127-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4127-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7, python3.4' package(s) announced via the USN-4127-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4127-1 fixed several vulnerabilities in Python. This update provides
the corresponding update for Ubuntu 12.04 ESM and Ubuntu 14.04 ESM.

Original advisory details:

 It was discovered that Python incorrectly handled certain pickle files. An
 attacker could possibly use this issue to consume memory, leading to a
 denial of service. This issue only affected Ubuntu 14.04 ESM. (CVE-2018-20406)

 It was discovered that Python incorrectly validated the domain when
 handling cookies. An attacker could possibly trick Python into sending
 cookies to the wrong domain. (CVE-2018-20852)

 Jonathan Birch and Panayiotis Panayiotou discovered that Python incorrectly
 handled Unicode encoding during NFKC normalization. An attacker could
 possibly use this issue to obtain sensitive information. (CVE-2019-9636,
 CVE-2019-10160)

 Colin Read and Nicolas Edet discovered that Python incorrectly handled
 parsing certain X509 certificates. An attacker could possibly use this
 issue to cause Python to crash, resulting in a denial of service. This
 issue only affected Ubuntu 14.04 ESM. (CVE-2019-5010)

 It was discovered that Python incorrectly handled certain urls. A remote
 attacker could possibly use this issue to perform CRLF injection attacks.
 (CVE-2019-9740, CVE-2019-9947)

 Sihoon Lee discovered that Python incorrectly handled the local_file:
 scheme. A remote attacker could possibly use this issue to bypass blocklist
 meschanisms. (CVE-2019-9948)");

  script_tag(name:"affected", value:"'python2.7, python3.4' package(s) on Ubuntu 12.04, Ubuntu 14.04.");

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

if(release == "UBUNTU12.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.3-0ubuntu3.14", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.3-0ubuntu3.14", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.6-8ubuntu0.6+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.6-8ubuntu0.6+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4-minimal", ver:"3.4.3-1ubuntu1~14.04.7+esm2", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3.4", ver:"3.4.3-1ubuntu1~14.04.7+esm2", rls:"UBUNTU14.04 LTS"))) {
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
