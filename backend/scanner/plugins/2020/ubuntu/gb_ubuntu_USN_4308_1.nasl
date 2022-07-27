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
  script_oid("1.3.6.1.4.1.25623.1.0.844371");
  script_version("2020-03-20T06:19:59+0000");
  script_cve_id("CVE-2019-12387", "CVE-2019-12855", "CVE-2019-9512", "CVE-2019-9514", "CVE-2019-9515", "CVE-2020-10108", "CVE-2020-10109");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-03-20 13:26:01 +0000 (Fri, 20 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-20 04:00:21 +0000 (Fri, 20 Mar 2020)");
  script_name("Ubuntu: Security Advisory for twisted (USN-4308-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU19\.10|UBUNTU18\.04 LTS|UBUNTU16\.04 LTS)");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2020-March/005367.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'twisted'
  package(s) announced via the USN-4308-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"it was discovered that Twisted incorrectly validated or sanitized certain
URIs or HTTP methods. A remote attacker could use this issue to inject
invalid characters and possibly perform header injection attacks.
(CVE-2019-12387)

It was discovered that Twisted incorrectly verified XMPP TLS certificates.
A remote attacker could possibly use this issue to perform a
man-in-the-middle attack and obtain sensitive information. (CVE-2019-12855)

It was discovered that Twisted incorrectly handled HTTP/2 connections. A
remote attacker could possibly use this issue to cause Twisted to hang or
consume resources, leading to a denial of service. This issue only affected
Ubuntu 18.04 LTS and Ubuntu 19.10. (CVE-2019-9512, CVE-2019-9514,
CVE-2019-9515)

Jake Miller and ZeddYu Lu discovered that Twisted incorrectly handled
certain content-length headers. A remote attacker could possibly use this
issue to perform HTTP request splitting attacks. (CVE-2020-10108,
CVE-2020-10109)");

  script_tag(name:"affected", value:"'twisted' package(s) on Ubuntu 19.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted", ver:"18.9.0-3ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted-bin", ver:"18.9.0-3ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted-web", ver:"18.9.0-3ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-twisted", ver:"18.9.0-3ubuntu1.1", rls:"UBUNTU19.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-twisted-bin", ver:"18.9.0-3ubuntu1.1", rls:"UBUNTU19.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted", ver:"17.9.0-2ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted-bin", ver:"17.9.0-2ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted-web", ver:"17.9.0-2ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-twisted", ver:"17.9.0-2ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-twisted-bin", ver:"17.9.0-2ubuntu0.1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted", ver:"16.0.0-1ubuntu0.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted-bin", ver:"16.0.0-1ubuntu0.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python-twisted-web", ver:"16.0.0-1ubuntu0.4", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-twisted", ver:"16.0.0-1ubuntu0.4", rls:"UBUNTU16.04 LTS"))) {
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