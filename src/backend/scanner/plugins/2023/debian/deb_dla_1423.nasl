# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2018.1423");
  script_cve_id("CVE-2017-18255", "CVE-2017-5753", "CVE-2018-1000204", "CVE-2018-10021", "CVE-2018-10087", "CVE-2018-10124", "CVE-2018-10853", "CVE-2018-10876", "CVE-2018-10877", "CVE-2018-10878", "CVE-2018-10879", "CVE-2018-10880", "CVE-2018-10881", "CVE-2018-10882", "CVE-2018-10883", "CVE-2018-10940", "CVE-2018-1118", "CVE-2018-1120", "CVE-2018-1130", "CVE-2018-11506", "CVE-2018-12233", "CVE-2018-3639", "CVE-2018-5814", "CVE-2018-6412");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:37:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-1423)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"Advisory-ID", value:"DLA-1423");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2018/dla-1423");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-4.9' package(s) announced via the DLA-1423 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Linux 4.9 has been packaged for Debian 8 as linux-4.9. This provides a supported upgrade path for systems that currently use kernel packages from the 'jessie-backports' suite.

There is no need to upgrade systems using Linux 3.16, as that kernel version will also continue to be supported in the LTS period.

This backport does not include the following binary packages:

hyperv-daemons libcpupower1 libcpupower-dev libusbip-dev linux-compiler-gcc-4.9-x86 linux-cpupower linux-libc-dev usbip

Older versions of most of those are built from other source packages in Debian 8.

Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2017-5753

Further instances of code that was vulnerable to Spectre variant 1 (bounds-check bypass) have been mitigated.

CVE-2017-18255

It was discovered that the performance events subsystem did not properly validate the value of the kernel.perf_cpu_time_max_percent sysctl. Setting a large value could have an unspecified security impact. However, only a privileged user can set this sysctl.

CVE-2018-1118

The syzbot software found that the vhost driver did not initialise message buffers which would later be read by user processes. A user with access to the /dev/vhost-net device could use this to read sensitive information from the kernel or other users' processes.

CVE-2018-1120

Qualys reported that a user able to mount FUSE filesystems can create a process such that when another process attempting to read its command line will be blocked for an arbitrarily long time. This could be used for denial of service, or to aid in exploiting a race condition in the other program.

CVE-2018-1130

The syzbot software found that the DCCP implementation of sendmsg() does not check the socket state, potentially leading to a null pointer dereference. A local user could use this to cause a denial of service (crash).

CVE-2018-3639

Multiple researchers have discovered that Speculative Store Bypass (SSB), a feature implemented in many processors, could be used to read sensitive information from another context. In particular, code in a software sandbox may be able to read sensitive information from outside the sandbox. This issue is also known as Spectre variant 4.

This update allows the issue to be mitigated on some x86 processors by disabling SSB. This requires an update to the processor's microcode, which is non-free. It may be included in an update to the system BIOS or UEFI firmware, or in a future update to the intel-microcode or amd64-microcode packages.

Disabling SSB can reduce performance significantly, so by default it is only done in tasks that use the seccomp feature. Applications that require this mitigation should request it explicitly through the prctl() system call. Users can control where the mitigation is enabled with the spec_store_bypass_disable ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-4.9' package(s) on Debian 8.");

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

if(release == "DEB8") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-arm", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686-pae", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-686", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-amd64", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armel", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-armhf", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all-i386", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-all", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-amd64", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-armmp", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common-rt", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-common", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-marvell", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae-dbg", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686-pae", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-686", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64-dbg", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-amd64", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp-lpae", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-armmp", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-marvell", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae-dbg", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-686-pae", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64-dbg", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-0.bpo.7-rt-amd64", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-0.bpo.7", ver:"4.9.110-1~deb8u1", rls:"DEB8"))) {
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
