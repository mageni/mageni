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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2021.4467.2");
  script_cve_id("CVE-2020-13253", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13754", "CVE-2020-14364");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-14 20:31:00 +0000 (Mon, 14 Dec 2020)");

  script_name("Ubuntu: Security Advisory (USN-4467-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4467-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4467-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-4467-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4467-1 fixed several vulnerabilities in QEMU. This update provides
the corresponding update for Ubuntu 14.04 ESM.

Original advisory details:

 It was discovered that the QEMU SD memory card implementation incorrectly
 handled certain memory operations. An attacker inside a guest could
 possibly use this issue to cause QEMU to crash, resulting in a denial of
 service. (CVE-2020-13253)

 Ren Ding and Hanqing Zhao discovered that the QEMU ES1370 audio driver
 incorrectly handled certain invalid frame counts. An attacker inside a
 guest could possibly use this issue to cause QEMU to crash, resulting in a
 denial of service. (CVE-2020-13361)

 Ren Ding and Hanqing Zhao discovered that the QEMU MegaRAID SAS SCSI driver
 incorrectly handled certain memory operations. An attacker inside a guest
 could possibly use this issue to cause QEMU to crash, resulting in a denial
 of service. (CVE-2020-13362)

 Alexander Bulekov discovered that QEMU MegaRAID SAS SCSI driver incorrectly
 handled certain memory space operations. An attacker inside a guest could
 possibly use this issue to cause QEMU to crash, resulting in a denial of
 service. (CVE-2020-13659)

 Ren Ding, Hanqing Zhao, Alexander Bulekov, and Anatoly Trosinenko
 discovered that the QEMU incorrectly handled certain msi-x mmio operations.
 An attacker inside a guest could possibly use this issue to cause QEMU to
 crash, resulting in a denial of service. (CVE-2020-13754)

 Ziming Zhang, Xiao Wei, Gonglei Arei and Yanyu Zhang discovered that
 QEMU incorrectly handled certain USB packets. An attacker could possibly
 use this to expose sensitive information or execute arbitrary code.
 (CVE-2020-14364)");

  script_tag(name:"affected", value:"'qemu' package(s) on Ubuntu 14.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-aarch64", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"2.0.0+dfsg-2ubuntu1.47+esm1", rls:"UBUNTU14.04 LTS"))) {
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
