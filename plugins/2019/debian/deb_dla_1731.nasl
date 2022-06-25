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
  script_oid("1.3.6.1.4.1.25623.1.0.891731");
  script_version("2019-04-02T06:16:35+0000");
  script_cve_id("CVE-2016-10741", "CVE-2017-13305", "CVE-2017-5753", "CVE-2018-12896", "CVE-2018-13053", "CVE-2018-16862", "CVE-2018-16884", "CVE-2018-17972", "CVE-2018-18281", "CVE-2018-18690", "CVE-2018-18710", "CVE-2018-19824", "CVE-2018-19985", "CVE-2018-20169", "CVE-2018-20511", "CVE-2018-3639", "CVE-2018-5848", "CVE-2018-5953", "CVE-2019-3701", "CVE-2019-3819", "CVE-2019-6974", "CVE-2019-7221", "CVE-2019-7222", "CVE-2019-9213");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-04-02 06:16:35 +0000 (Tue, 02 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-03-27 23:00:00 +0100 (Wed, 27 Mar 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1731-1] linux security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00034.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1731-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-1731-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2016-10741

A race condition was discovered in XFS that would result in a
crash (BUG). A local user permitted to write to an XFS volume
could use this for denial of service.

CVE-2017-5753

Further instances of code that was vulnerable to Spectre variant 1
(bounds-check bypass) have been mitigated.

CVE-2017-13305

A memory over-read was discovered in the keys subsystem's
encrypted key type. A local user could use this for denial of
service or possibly to read sensitive information.

CVE-2018-3639 (SSB)

Multiple researchers have discovered that Speculative Store Bypass
(SSB), a feature implemented in many processors, could be used to
read sensitive information from another context. In particular,
code in a software sandbox may be able to read sensitive
information from outside the sandbox. This issue is also known as
Spectre variant 4.

This update fixes bugs in the mitigations for SSB for AMD
processors.

CVE-2018-5848

The wil6210 wifi driver did not properly validate lengths in scan
and connection requests, leading to a possible buffer overflow.
On systems using this driver, a local user with the CAP_NET_ADMIN
capability could use this for denial of service (memory corruption
or crash) or potentially for privilege escalation.

CVE-2018-5953

The swiotlb subsystem printed kernel memory addresses to the
system log, which could help a local attacker to exploit other
vulnerabilities.

CVE-2018-12896, CVE-2018-13053

Team OWL337 reported possible integer overflows in the POSIX
timer implementation. These might have some security impact.

CVE-2018-16862

Vasily Averin and Pavel Tikhomirov from Virtuozzo Kernel Team
discovered that the cleancache memory management feature did not
invalidate cached data for deleted files. On Xen guests using the
tmem driver, local users could potentially read data from other
users' deleted files if they were able to create new files on the
same volume.

CVE-2018-16884

A flaw was found in the NFS 4.1 client implementation. Mounting
NFS shares in multiple network namespaces at the same time could
lead to a user-after-free. Local users might be able to use this
for denial of service (memory corruption or crash) or possibly
for privilege escalation.

This can be mitigated by disabling unprivileged users from
creating user namespaces, which is the default in Debian.

CVE-2018-17972

Jann Horn reported that the /proc/*/stack files in procfs leaked
sensitive data from the kernel. These files are now only readable
by users with the CAP_SYS_AD ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.16.64-1.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-arm", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-x86", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-x86", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.16", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armel", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-armhf", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-all-i386", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-common", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-4-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-armel", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-armhf", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-all-i386", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-common", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-5-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-armel", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-armhf", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-all-i386", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-common", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-6-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-armel", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-armhf", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-all-i386", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-common", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-7-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-armel", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-armhf", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-all-i386", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-common", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-8-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-686-pae-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-amd64-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-4-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-686-pae-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-amd64-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-5-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-686-pae-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-amd64-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-6-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-686-pae-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-amd64-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-7-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-586", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-686-pae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-686-pae-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-amd64-dbg", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-armmp", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-armmp-lpae", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-ixp4xx", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-kirkwood", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-orion5x", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-8-versatile", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.16", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.16", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-4", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-6", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-7", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-8", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-4-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-5-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-6-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-7-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-8-amd64", ver:"3.16.64-1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);