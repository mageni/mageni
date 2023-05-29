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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3404");
  script_cve_id("CVE-2022-2196", "CVE-2022-3424", "CVE-2022-3707", "CVE-2022-4129", "CVE-2022-4379", "CVE-2023-0045", "CVE-2023-0458", "CVE-2023-0459", "CVE-2023-0461", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1078", "CVE-2023-1079", "CVE-2023-1118", "CVE-2023-1281", "CVE-2023-1513", "CVE-2023-1611", "CVE-2023-1670", "CVE-2023-1829", "CVE-2023-1855", "CVE-2023-1859", "CVE-2023-1872", "CVE-2023-1989", "CVE-2023-1990", "CVE-2023-1998", "CVE-2023-2162", "CVE-2023-2194", "CVE-2023-22998", "CVE-2023-23004", "CVE-2023-23559", "CVE-2023-25012", "CVE-2023-26545", "CVE-2023-28328", "CVE-2023-28466", "CVE-2023-30456");
  script_tag(name:"creation_date", value:"2023-05-17 04:23:53 +0000 (Wed, 17 May 2023)");
  script_version("2023-05-17T09:09:49+0000");
  script_tag(name:"last_modification", value:"2023-05-17 09:09:49 +0000 (Wed, 17 May 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 14:12:00 +0000 (Fri, 13 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-3404)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3404");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3404");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-5.10");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-5.10' package(s) announced via the DLA-3404 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service, or information leak.

CVE-2022-2196

A regression was discovered the KVM implementation for Intel CPUs, affecting Spectre v2 mitigation for nested virtualisation. When KVM was used as the L0 hypervisor, an L2 guest could exploit this to leak sensitive information from its L1 hypervisor.

CVE-2022-3424

Zheng Wang and Zhuorao Yang reported a flaw in the SGI GRU driver which could lead to a use-after-free. On systems where this driver is used, a local user can explit this for denial of service (crash or memory corruption) or possibly for privilege escalation.

This driver is not enabled in Debian's official kernel configurations.

CVE-2022-3707

Zheng Wang reported a flaw in the i915 graphics driver's virtualisation (GVT-g) support that could lead to a double-free. On systems where this feature is used, a guest can exploit this for denial of service (crash or memory corruption) or possibly for privilege escalation.

CVE-2022-4129

Haowei Yan reported a race condition in the L2TP protocol implementation which could lead to a null pointer dereference. A local user could exploit this for denial of service (crash).

CVE-2022-4379

Xingyuan Mo reported a flaw in the NFSv4.2 inter server to server copy implementation which could lead to a use-after-free.

This feature is not enabled in Debian's official kernel configurations.

CVE-2023-0045

Rodrigo Branco and Rafael Correa De Ysasi reported that when a user-space task told the kernel to enable Spectre v2 mitigation for it, the mitigation was not enabled until the task was next rescheduled. This might be exploitable by a local or remote attacker to leak sensitive information from such an application.

CVE-2023-0458

Jordy Zimmer and Alexandra Sandulescu found that getrlimit() and related system calls were vulnerable to speculative execution attacks such as Spectre v1. A local user could explot this to leak sensitive information from the kernel.

CVE-2023-0459

Jordy Zimmer and Alexandra Sandulescu found a regression in Spectre v1 mitigation in the user-copy functions for the amd64 (64-bit PC) architecture. Where the CPUs do not implement SMAP or it is disabled, a local user could exploit this to leak sensitive information from the kernel. Other architectures may also be affected.

CVE-2023-0461

slipper reported a flaw in the kernel's support for ULPs (Upper Layer Protocols) on top of TCP that can lead to a double-free when using kernel TLS sockets. A local user can exploit this for denial of service (crash or memory corruption) or possibly for privilege escalation.

Kernel TLS is not enabled in Debian's official kernel configurations.

CVE-2023-1073

Pietro Borrello reported a type confusion flaw in the HID (Human Interface Device) subsystem. An attacker able to insert and remove USB devices might be able ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-5.10' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp-lpae", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-rt-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-686-pae", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-686", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-amd64", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-arm64", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-armmp-lpae", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-cloud-amd64", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-cloud-arm64", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-common-rt", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-common", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-rt-686-pae", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-rt-amd64", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-rt-arm64", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.22-rt-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-pae-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-signed-template", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-signed-template", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-amd64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-arm64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-i386-signed-template", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-686-pae-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-amd64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-arm64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-686-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-686-pae-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-686-pae-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-686-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-amd64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-amd64-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-arm64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-arm64-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-armmp-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-armmp-lpae-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-armmp-lpae", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-cloud-amd64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-cloud-amd64-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-cloud-arm64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-cloud-arm64-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-686-pae-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-686-pae-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-amd64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-amd64-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-arm64-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-arm64-unsigned", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-armmp-dbg", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.22-rt-armmp", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.22", ver:"5.10.178-3~deb10u1", rls:"DEB10"))) {
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
