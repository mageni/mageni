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
  script_oid("1.3.6.1.4.1.25623.1.0.844068");
  script_version("2019-06-27T06:30:18+0000");
  script_cve_id("CVE-2018-14662", "CVE-2018-16846", "CVE-2018-16889", "CVE-2019-3821");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-06-27 06:30:18 +0000 (Thu, 27 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-26 02:00:59 +0000 (Wed, 26 Jun 2019)");
  script_name("Ubuntu Update for ceph USN-4035-1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU18\.10|UBUNTU19\.04|UBUNTU16\.04 LTS)");

  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2019-June/004982.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ceph'
  package(s) announced via the USN-4035-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ceph incorrectly handled read only permissions. An
authenticated attacker could use this issue to obtain dm-crypt encryption
keys. This issue only affected Ubuntu 16.04 LTS. (CVE-2018-14662)

It was discovered that Ceph incorrectly handled certain OMAPs holding
bucket indices. An authenticated attacker could possibly use this issue to
cause a denial of service. This issue only affected Ubuntu 16.04 LTS.
(CVE-2018-16846)

It was discovered that Ceph incorrectly sanitized certain debug logs. A
local attacker could possibly use this issue to obtain encryption key
information. This issue was only addressed in Ubuntu 18.10 and Ubuntu
19.04. (CVE-2018-16889)

It was discovered that Ceph incorrectly handled certain civetweb requests.
A remote attacker could possibly use this issue to consume resources,
leading to a denial of service. This issue only affected Ubuntu 18.10 and
Ubuntu 19.04. (CVE-2019-3821)");

  script_tag(name:"affected", value:"'ceph' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 16.04 LTS.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"13.2.4+dfsg1-0ubuntu0.18.10.2", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"13.2.4+dfsg1-0ubuntu0.18.10.2", rls:"UBUNTU18.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"13.2.4+dfsg1-0ubuntu2.1", rls:"UBUNTU19.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"13.2.4+dfsg1-0ubuntu2.1", rls:"UBUNTU19.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"ceph", ver:"10.2.11-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ceph-common", ver:"10.2.11-0ubuntu0.16.04.2", rls:"UBUNTU16.04 LTS"))) {
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