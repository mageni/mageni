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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2017.3422.2");
  script_cve_id("CVE-2016-10044", "CVE-2016-10200", "CVE-2016-7097", "CVE-2016-8650", "CVE-2016-9083", "CVE-2016-9084", "CVE-2016-9178", "CVE-2016-9191", "CVE-2016-9604", "CVE-2016-9754", "CVE-2017-1000251", "CVE-2017-5970", "CVE-2017-6214", "CVE-2017-6346", "CVE-2017-6951", "CVE-2017-7187", "CVE-2017-7472", "CVE-2017-7541");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-08-26T07:43:23+0000");
  script_tag(name:"last_modification", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.7");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-06-03 19:00:00 +0000 (Wed, 03 Jun 2020)");

  script_name("Ubuntu: Security Advisory (USN-3422-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU12\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-3422-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3422-2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-lts-trusty' package(s) announced via the USN-3422-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3422-1 fixed vulnerabilities in the Linux kernel for Ubuntu 14.04
LTS. This update provides the corresponding updates for the Linux
Hardware Enablement (HWE) kernel from Ubuntu 14.04 LTS for Ubuntu
12.04 LTS.

It was discovered that a buffer overflow existed in the Bluetooth stack of
the Linux kernel when handling L2CAP configuration responses. A physically
proximate attacker could use this to cause a denial of service (system
crash). (CVE-2017-1000251)

It was discovered that the asynchronous I/O (aio) subsystem of the Linux
kernel did not properly set permissions on aio memory mappings in some
situations. An attacker could use this to more easily exploit other
vulnerabilities. (CVE-2016-10044)

Baozeng Ding and Andrey Konovalov discovered a race condition in the L2TPv3
IP Encapsulation implementation in the Linux kernel. A local attacker could
use this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2016-10200)

Andreas Gruenbacher and Jan Kara discovered that the filesystem
implementation in the Linux kernel did not clear the setgid bit during a
setxattr call. A local attacker could use this to possibly elevate group
privileges. (CVE-2016-7097)

Sergej Schumilo, Ralf Spenneberg, and Hendrik Schwartke discovered that the
key management subsystem in the Linux kernel did not properly allocate
memory in some situations. A local attacker could use this to cause a
denial of service (system crash). (CVE-2016-8650)

Vlad Tsyrklevich discovered an integer overflow vulnerability in the VFIO
PCI driver for the Linux kernel. A local attacker with access to a vfio PCI
device file could use this to cause a denial of service (system crash) or
possibly execute arbitrary code. (CVE-2016-9083, CVE-2016-9084)

It was discovered that an information leak existed in __get_user_asm_ex()
in the Linux kernel. A local attacker could use this to expose sensitive
information. (CVE-2016-9178)

CAI Qian discovered that the sysctl implementation in the Linux kernel did
not properly perform reference counting in some situations. An unprivileged
attacker could use this to cause a denial of service (system hang).
(CVE-2016-9191)

It was discovered that the keyring implementation in the Linux kernel in
some situations did not prevent special internal keyrings from being joined
by userspace keyrings. A privileged local attacker could use this to bypass
module verification. (CVE-2016-9604)

It was discovered that an integer overflow existed in the trace subsystem
of the Linux kernel. A local privileged attacker could use this to cause a
denial of service (system crash). (CVE-2016-9754)

Andrey Konovalov discovered that the IPv4 implementation in the Linux
kernel did not properly handle invalid IP options in some situations. An
attacker could use this to cause a denial of service or possibly execute
arbitrary code. (CVE-2017-5970)

Dmitry Vyukov discovered that the ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-lts-trusty' package(s) on Ubuntu 12.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-132-generic-lpae", ver:"3.13.0-132.181~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.13.0-132-generic", ver:"3.13.0-132.181~precise1", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-lts-trusty", ver:"3.13.0.132.122", rls:"UBUNTU12.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-trusty", ver:"3.13.0.132.122", rls:"UBUNTU12.04 LTS"))) {
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
