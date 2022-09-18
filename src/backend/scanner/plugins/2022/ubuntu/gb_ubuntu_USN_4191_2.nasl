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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.4191.2");
  script_cve_id("CVE-2019-12068", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-15890");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_name("Ubuntu: Security Advisory (USN-4191-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU14\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-4191-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4191-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the USN-4191-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-4191-2 fixed a vulnerability in QEMU. This update provides the
corresponding update for Ubuntu 14.04 ESM.

Original advisory details:

 It was discovered that the LSI SCSI adapter emulator implementation in QEMU
 did not properly validate executed scripts. A local attacker could use this
 to cause a denial of service. (CVE-2019-12068)

 Sergej Schumilo, Cornelius Aschermann and Simon Worner discovered that the
 qxl paravirtual graphics driver implementation in QEMU contained a null
 pointer dereference. A local attacker in a guest could use this to cause a
 denial of service. (CVE-2019-12155)

 Riccardo Schirone discovered that the QEMU bridge helper did not properly
 validate network interface names. A local attacker could possibly use this
 to bypass ACL restrictions. (CVE-2019-13164)

 It was discovered that a heap-based buffer overflow existed in the SLiRP
 networking implementation of QEMU. A local attacker in a guest could use
 this to cause a denial of service or possibly execute arbitrary code in the
 host. (CVE-2019-14378)

 It was discovered that a use-after-free vulnerability existed in the SLiRP
 networking implementation of QEMU. A local attacker in a guest could use
 this to cause a denial of service. (CVE-2019-15890)");

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

  if(!isnull(res = isdpkgvuln(pkg:"qemu-common", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"2.0.0+dfsg-2ubuntu1.47", rls:"UBUNTU14.04 LTS"))) {
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
