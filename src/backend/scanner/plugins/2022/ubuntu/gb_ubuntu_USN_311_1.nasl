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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.311.1");
  script_cve_id("CVE-2006-0039", "CVE-2006-2445", "CVE-2006-2448", "CVE-2006-2451");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:N/A:C");

  script_name("Ubuntu: Security Advisory (USN-311-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10|6\.06\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-311-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-311-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-meta, linux-restricted-modules-2.6.15, linux-source-2.6.10, linux-source-2.6.12, linux-source-2.6.15' package(s) announced via the USN-311-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A race condition was discovered in the do_add_counters() functions.
Processes which do not run with full root privileges, but have the
CAP_NET_ADMIN capability can exploit this to crash the machine or read
a random piece of kernel memory. In Ubuntu there are no packages that
are affected by this, so this can only be an issue for you if you use
third-party software that uses Linux capabilities. (CVE-2006-0039)

John Stultz discovered a faulty BUG_ON trigger in the handling of
POSIX timers. A local attacker could exploit this to trigger a kernel
oops and crash the machine. (CVE-2006-2445)

Dave Jones discovered that the PowerPC kernel did not perform certain
required access_ok() checks. A local user could exploit this to read
arbitrary kernel memory and crash the kernel on 64-bit systems, and
possibly read arbitrary kernel memory on 32-bit systems.
(CVE-2006-2448)

A design flaw was discovered in the prctl(PR_SET_DUMPABLE, ...) system
call, which allowed a local user to have core dumps created in a
directory he could not normally write to. This could be exploited to
drain available disk space on system partitions, or, under some
circumstances, to execute arbitrary code with full root privileges.
This flaw only affects Ubuntu 6.06 LTS. (CVE-2006-2451)

In addition, the Ubuntu 6.06 LTS update fixes a range of bugs.");

  script_tag(name:"affected", value:"'linux-meta, linux-restricted-modules-2.6.15, linux-source-2.6.10, linux-source-2.6.12, linux-source-2.6.15' package(s) on Ubuntu 5.04, Ubuntu 5.10, Ubuntu 6.06.");

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

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-386", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-686-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-686", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-generic", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-k8-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-k8", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-amd64-xeon", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa32-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa32", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa64-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-hppa64", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-itanium-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-itanium", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-k7-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-k7", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-mckinley-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-mckinley", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power3-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power3", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power4-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-power4", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-powerpc-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-powerpc", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-sparc64-smp", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.10-6-sparc64", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.10", ver:"2.6.10-34.21", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-386", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-686", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-generic", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-k8", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-amd64-xeon", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa32-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa32", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa64-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-hppa64", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-iseries-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-itanium-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-itanium", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-k7", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-mckinley-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-mckinley", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-powerpc64-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-sparc64-smp", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.12-10-sparc64", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-ubuntu-2.6.12", ver:"2.6.12-10.35", rls:"UBUNTU5.10"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU6.06 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-386", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-686", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-generic", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-k8", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-server", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-amd64-xeon", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa32-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa32", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa64-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-hppa64", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-itanium-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-itanium", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-k7", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-mckinley-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-mckinley", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-powerpc-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-powerpc", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-powerpc64-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-server-bigiron", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-server", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-sparc64-smp", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.15-26-sparc64", ver:"2.6.15-26.44", rls:"UBUNTU6.06 LTS"))) {
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
