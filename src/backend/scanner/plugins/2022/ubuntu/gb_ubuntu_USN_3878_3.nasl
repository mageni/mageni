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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2019.3878.3");
  script_cve_id("CVE-2018-14625", "CVE-2018-16882", "CVE-2018-19407", "CVE-2018-19854");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-16T08:45:11+0000");
  script_tag(name:"last_modification", value:"2022-09-16 08:45:11 +0000 (Fri, 16 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:36:00 +0000 (Wed, 09 Oct 2019)");

  script_name("Ubuntu: Security Advisory (USN-3878-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|18\.10)");

  script_xref(name:"Advisory-ID", value:"USN-3878-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-3878-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/1814555");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-hwe' package(s) announced via the USN-3878-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-3878-1 fixed vulnerabilities in the Linux kernel. Unfortunately,
that update introduced a regression that could prevent systems with
certain graphics chipsets from booting. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that a race condition existed in the vsock address family
 implementation of the Linux kernel that could lead to a use-after-free
 condition. A local attacker in a guest virtual machine could use this to
 expose sensitive information (host machine kernel memory). (CVE-2018-14625)

 Cfir Cohen discovered that a use-after-free vulnerability existed in the
 KVM implementation of the Linux kernel, when handling interrupts in
 environments where nested virtualization is in use (nested KVM
 virtualization is not enabled by default in Ubuntu kernels). A local
 attacker in a guest VM could possibly use this to gain administrative
 privileges in a host machine. (CVE-2018-16882)

 Wei Wu discovered that the KVM implementation in the Linux kernel did not
 properly ensure that ioapics were initialized. A local attacker could use
 this to cause a denial of service (system crash). (CVE-2018-19407)

 It was discovered that the crypto subsystem of the Linux kernel leaked
 uninitialized memory to user space in some situations. A local attacker
 could use this to expose sensitive information (kernel memory).
 (CVE-2018-19854)");

  script_tag(name:"affected", value:"'linux, linux-hwe' package(s) on Ubuntu 18.04, Ubuntu 18.10.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-generic-lpae", ver:"4.18.0-15.16~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-generic", ver:"4.18.0-15.16~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-lowlatency", ver:"4.18.0-15.16~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-snapdragon", ver:"4.18.0-15.16~18.04.1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-hwe-18.04", ver:"4.18.0.15.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae-hwe-18.04", ver:"4.18.0.15.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-hwe-18.04", ver:"4.18.0.15.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon-hwe-18.04", ver:"4.18.0.15.65", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-generic-lpae", ver:"4.18.0-15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-generic", ver:"4.18.0-15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-lowlatency", ver:"4.18.0-15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.18.0-15-snapdragon", ver:"4.18.0-15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lpae", ver:"4.18.0.15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.18.0.15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.18.0.15.16", rls:"UBUNTU18.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-snapdragon", ver:"4.18.0.15.16", rls:"UBUNTU18.10"))) {
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
