# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892494");
  script_version("2020-12-19T04:00:22+0000");
  script_cve_id("CVE-2020-0427", "CVE-2020-14351", "CVE-2020-25645", "CVE-2020-25656", "CVE-2020-25668", "CVE-2020-25669", "CVE-2020-25704", "CVE-2020-25705", "CVE-2020-27673", "CVE-2020-27675", "CVE-2020-28974", "CVE-2020-8694");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-12-19 04:00:22 +0000 (Sat, 19 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-19 04:00:22 +0000 (Sat, 19 Dec 2020)");
  script_name("Debian LTS: Security Advisory for linux (DLA-2494-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/12/msg00027.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2494-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DLA-2494-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to the execution of arbitrary code, privilege escalation,
denial of service or information leaks.

CVE-2020-0427

Elena Petrova reported a bug in the pinctrl subsystem that can
lead to a use-after-free after a device is renamed. The security
impact of this is unclear.

CVE-2020-8694

Multiple researchers discovered that the powercap subsystem
allowed all users to read CPU energy meters, by default. On
systems using Intel CPUs, this provided a side channel that could
leak sensitive information between user processes, or from the
kernel to user processes. The energy meters are now readable only
by root, by default.

This issue can be mitigated by running:

chmod go-r /sys/devices/virtual/powercap/*/*/energy_uj

This needs to be repeated each time the system is booted with
an unfixed kernel version.

CVE-2020-14351

A race condition was discovered in the performance events
subsystem, which could lead to a use-after-free. A local user
permitted to access performance events could use this to cause a
denial of service (crash or memory corruption) or possibly for
privilege escalation.

Debian's kernel configuration does not allow unprivileged users to
access performance events by default, which fully mitigates this
issue.

CVE-2020-25645

A flaw was discovered in the interface driver for GENEVE
encapsulated traffic when combined with IPsec. If IPsec is
configured to encrypt traffic for the specific UDP port used by the
GENEVE tunnel, tunneled data isn't correctly routed over the
encrypted link and sent unencrypted instead.

CVE-2020-25656

Yuan Ming and Bodong Zhao discovered a race condition in the
virtual terminal (vt) driver that could lead to a use-after-free.
A local user with the CAP_SYS_TTY_CONFIG capability could use this
to cause a denial of service (crash or memory corruption) or
possibly for privilege escalation.

CVE-2020-25668

Yuan Ming and Bodong Zhao discovered a race condition in the
virtual terminal (vt) driver that could lead to a use-after-free.
A local user with access to a virtual terminal, or with the
CAP_SYS_TTY_CONFIG capability, could use this to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation.

CVE-2020-25669

Bodong Zhao discovered a bug in the Sun keyboard driver (sunkbd)
that could lead to a use-after-free. On a system using this
driver, a local user could use this to cause a denial of service
(crash or memory corruption) or possibly for privilege escalation.

CVE-2020-25704

kiyini discovered a potential memory leak in the performance
events subsystem. A local user perm ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
4.9.246-2.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"hyperv-daemons", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower-dev", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libcpupower1", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libusbip-dev", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-arm", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-6-x86", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-cpupower", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-4.9", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-686", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-armel", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-armhf", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-all-i386", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-armmp", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-armmp-lpae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-common", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-common-rt", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-marvell", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-rt-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-11-rt-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-686", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-all", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-all-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-all-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-all-armel", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-all-armhf", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-all-i386", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-armmp", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-armmp-lpae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-common", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-common-rt", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-marvell", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-rt-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-12-rt-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-686", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-armel", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-armhf", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-all-i386", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-armmp", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-armmp-lpae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-common", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-common-rt", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-marvell", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-rt-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-4.9.0-14-rt-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-686-pae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-amd64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-arm64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp-lpae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-armmp-lpae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-marvell", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-marvell-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-686-pae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-11-rt-amd64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-686", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-686-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-686-pae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-amd64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-arm64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-armmp", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-armmp-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-armmp-lpae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-armmp-lpae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-marvell", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-marvell-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-rt-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-rt-686-pae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-rt-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-12-rt-amd64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-686-pae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-amd64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-arm64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-arm64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp-lpae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-armmp-lpae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-marvell", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-marvell-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-686-pae", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-686-pae-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-amd64", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.9.0-14-rt-amd64-dbg", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-4.9", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-4.9", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-4.9", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-4.9", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-11", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-12", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-4.9.0-14", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"usbip", ver:"4.9.246-2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
