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
  script_oid("1.3.6.1.4.1.25623.1.0.845417");
  script_version("2022-06-21T14:04:09+0000");
  script_cve_id("CVE-2021-0127", "CVE-2021-0145", "CVE-2021-0146", "CVE-2021-33117", "CVE-2021-33120", "CVE-2022-21123", "CVE-2022-21127", "CVE-2022-21151", "CVE-2022-21166");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-06-21 14:04:09 +0000 (Tue, 21 Jun 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-15 17:50:00 +0000 (Tue, 15 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-06-21 01:00:45 +0000 (Tue, 21 Jun 2022)");
  script_name("Ubuntu: Security Advisory for intel-microcode (USN-5486-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=(UBUNTU21\.10|UBUNTU18\.04 LTS|UBUNTU22\.04 LTS|UBUNTU20\.04 LTS)");

  script_xref(name:"Advisory-ID", value:"USN-5486-1");
  script_xref(name:"URL", value:"https://lists.ubuntu.com/archives/ubuntu-security-announce/2022-June/006636.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'intel-microcode'
  package(s) announced via the USN-5486-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that some Intel processors did not implement sufficient
control flow management. A local attacker could use this to cause a denial
of service. (CVE-2021-0127)

Joseph Nuzman discovered that some Intel processors did not properly
initialise shared resources. A local attacker could use this to obtain
sensitive information. (CVE-2021-0145)

Mark Ermolov, Dmitry Sklyarov and Maxim Goryachy discovered that some Intel
processors did not prevent test and debug logic from being activated at
runtime. A local attacker could use this to escalate
privileges. (CVE-2021-0146)

It was discovered that some Intel processors did not properly restrict
access in some situations. A local attacker could use this to obtain
sensitive information. (CVE-2021-33117)

Brandon Miller discovered that some Intel processors did not properly
restrict access in some situations. A local attacker could use this to
obtain sensitive information or a remote attacker could use this to cause a
denial of service. (CVE-2021-33120)

It was discovered that some Intel processors did not completely perform
cleanup actions on multi-core shared buffers. A local attacker could
possibly use this to expose sensitive information. (CVE-2022-21123,
CVE-2022-21127)

Alysa Milburn, Jason Brandt, Avishai Redelman and Nir Lavi discovered that
some Intel processors improperly optimised security-critical code. A local
attacker could possibly use this to expose sensitive
information. (CVE-2022-21151)

It was discovered that some Intel processors did not properly perform
cleanup during specific special register write operations. A local attacker
could possibly use this to expose sensitive information. (CVE-2022-21166)");

  script_tag(name:"affected", value:"'intel-microcode' package(s) on Ubuntu 22.04 LTS, Ubuntu 21.10, Ubuntu 20.04 LTS, Ubuntu 18.04 LTS.");

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

if(release == "UBUNTU21.10") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20220510.0ubuntu0.21.10.1", rls:"UBUNTU21.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20220510.0ubuntu0.18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20220510.0ubuntu0.22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20220510.0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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