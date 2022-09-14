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
  script_oid("1.3.6.1.4.1.25623.1.0.893102");
  script_version("2022-09-13T08:42:55+0000");
  script_cve_id("CVE-2022-2585", "CVE-2022-2586", "CVE-2022-2588", "CVE-2022-26373", "CVE-2022-29900", "CVE-2022-29901", "CVE-2022-36879", "CVE-2022-36946");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-09-13 08:42:55 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-22 21:54:00 +0000 (Fri, 22 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-09-12 01:00:15 +0000 (Mon, 12 Sep 2022)");
  script_name("Debian LTS: Security Advisory for linux-5.10 (DLA-3102-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/09/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3102-1");
  script_xref(name:"Advisory-ID", value:"DLA-3102-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-5.10'
  package(s) announced via the DLA-3102-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linux 5.10 has been packaged for Debian 10 as linux-5.10. This
provides a supported upgrade path for systems that currently use
kernel packages from the 'buster-backports' suite.

There is no need to upgrade systems using Linux 4.19, as that kernel
version will also continue to be supported in the LTS period.

The 'apt full-upgrade' command will *not* automatically install the
updated kernel packages. You should explicitly install one of the
following metapackages first, as appropriate for your system:

linux-image-5.10-686
linux-image-5.10-686-pae
linux-image-5.10-amd64
linux-image-5.10-arm64
linux-image-5.10-armmp
linux-image-5.10-armmp-lpae
linux-image-5.10-cloud-amd64
linux-image-5.10-cloud-arm64
linux-image-5.10-rt-686-pae
linux-image-5.10-rt-amd64
linux-image-5.10-rt-arm64
linux-image-5.10-rt-armmp

For example, if the command 'uname -r' currently shows
'5.10.0-0.deb10.16-amd64', you should install linux-image-5.10-amd64.

This backport does not include the following binary packages:

bpftool hyperv-daemons libcpupower-dev libcpupower1
linux-compiler-gcc-8-arm linux-compiler-gcc-8-x86 linux-cpupower
linux-libc-dev usbip

Older versions of most of those are built from the linux source
package in Debian 10.

Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2022-2585

A use-after-free flaw in the implementation of POSIX CPU timers
may result in denial of service or in local privilege escalation.

CVE-2022-2586

A use-after-free in the Netfilter subsystem may result in local
privilege escalation for a user with the CAP_NET_ADMIN capability
in any user or network namespace.

CVE-2022-2588

Zhenpeng Lin discovered a use-after-free flaw in the cls_route
filter implementation which may result in local privilege
escalation for a user with the CAP_NET_ADMIN capability in any
user or network namespace.

CVE-2022-26373

It was discovered that on certain processors with Intel's Enhanced
Indirect Branch Restricted Speculation (eIBRS) capabilities there
are exceptions to the documented properties in some situations,
which may result in information disclosure.

Intel's explanation of the issue can be found at

CVE-2022-29900

Johannes Wikner and Kaveh Razavi reported that for AMD/Hygon
processors, mis-trained branch predictions for return instructions
may allow arbitrary speculative code execution under certain
microarchitecture-dependent conditions.

A list of affected AMD CPU types can be found at

CVE-2022-29901

Johannes Wikner and Kaveh Razavi reported that for Intel
processors (Intel Core generation 6, 7 and 8), prot ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-5.10' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
5.10.136-1~deb10u3. This update additionally includes many more bug
fixes from stable updates 5.10.128-5.10.136 inclusive.

We recommend that you upgrade your linux-5.10 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp-lpae", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-rt-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-686", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-686-pae", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-amd64", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-arm64", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-armmp-lpae", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-cloud-amd64", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-cloud-arm64", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-common", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-common-rt", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-686-pae", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-amd64", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-arm64", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-pae-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-signed-template", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-signed-template", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-amd64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-arm64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-i386-signed-template", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-686-pae-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-amd64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-arm64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-pae-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-pae-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-amd64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-amd64-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-arm64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-arm64-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-lpae", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-amd64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-arm64-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-armmp", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-armmp-dbg", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.17", ver:"5.10.136-1~deb10u3", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
