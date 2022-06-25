# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.891823");
  script_version("2019-06-18T02:00:44+0000");
  script_cve_id("CVE-2019-10126", "CVE-2019-11477", "CVE-2019-11478", "CVE-2019-11479", "CVE-2019-11810", "CVE-2019-11833", "CVE-2019-11884", "CVE-2019-3846", "CVE-2019-5489");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-18 02:00:44 +0000 (Tue, 18 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-18 02:00:44 +0000 (Tue, 18 Jun 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1823-1] linux security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00010.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1823-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-1823-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2019-3846, CVE-2019-10126

huangwen reported multiple buffer overflows in the Marvell wifi
(mwifiex) driver, which a local user could use to cause denial of
service or the execution of arbitrary code.

CVE-2019-5489

Daniel Gruss, Erik Kraft, Trishita Tiwari, Michael Schwarz, Ari
Trachtenberg, Jason Hennessey, Alex Ionescu, and Anders Fogh
discovered that local users could use the mincore() system call to
obtain sensitive information from other processes that access the
same memory-mapped file.

CVE-2019-11477

Jonathan Looney reported that a specially crafted sequence of TCP
selective acknowledgements (SACKs) allows a remotely triggerable
kernel panic.

CVE-2019-11478

Jonathan Looney reported that a specially crafted sequence of TCP
selective acknowledgements (SACKs) will fragment the TCP
retransmission queue, allowing an attacker to cause excessive
resource usage.

CVE-2019-11479

Jonathan Looney reported that an attacker could force the Linux
kernel to segment its responses into multiple TCP segments, each of
which contains only 8 bytes of data, drastically increasing the
bandwidth required to deliver the same amount of data.

This update introduces a new sysctl value to control the minimal MSS
(net.ipv4.tcp_min_snd_mss), which by default uses the formerly hard-
coded value of 48. We recommend raising this to 512 unless you know
that your network requires a lower value. (This value applies to
Linux 3.16 only.)

CVE-2019-11810

It was discovered that the megaraid_sas driver did not correctly
handle a failed memory allocation during initialisation, which
could lead to a double-free. This might have some security
impact, but it cannot be triggered by an unprivileged user.

CVE-2019-11833

It was discovered that the ext4 filesystem implementation writes
uninitialised data from kernel memory to new extent blocks. A
local user able to write to an ext4 filesystem and then read the
filesystem image, for example using a removable drive, might be
able to use this to obtain sensitive information.

CVE-2019-11884

It was discovered that the Bluetooth HIDP implementation did not
ensure that new connection names were null-terminated. A local
user with CAP_NET_ADMIN capability might be able to use this to
obtain sensitive information from the kernel stack.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.16.68-2. Packages for PC architectures (amd64 and i386) are already
available, and packages for Arm architectures (armel and armhf) will be
available soon.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-arm", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-x86", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-x86", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.16", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armel", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armhf", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-i386", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-common", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-armel", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-armhf", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-i386", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-common", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-armel", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-armhf", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-i386", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-common", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-armel", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-armhf", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-i386", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-common", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-armel", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-armhf", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-i386", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-common", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-all", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-all-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-all-armel", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-all-armhf", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-all-i386", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-common", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-9-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-686-pae-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-amd64-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-686-pae-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-amd64-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-686-pae-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-amd64-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-686-pae-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-amd64-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-586", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-686-pae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-686-pae-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-amd64-dbg", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-armmp", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-armmp-lpae", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-ixp4xx", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-kirkwood", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-orion5x", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-9-versatile", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.16", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.16", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-4", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-6", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-7", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-8", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-9", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-4-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-5-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-6-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-7-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-8-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-9-amd64", ver:"3.16.68-2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);