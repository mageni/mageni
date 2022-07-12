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
  script_oid("1.3.6.1.4.1.25623.1.0.891930");
  script_version("2019-09-26T02:00:36+0000");
  script_cve_id("CVE-2016-10905", "CVE-2018-20976", "CVE-2018-21008", "CVE-2019-0136", "CVE-2019-14814", "CVE-2019-14815", "CVE-2019-14816", "CVE-2019-14821", "CVE-2019-14835", "CVE-2019-15117", "CVE-2019-15118", "CVE-2019-15211", "CVE-2019-15212", "CVE-2019-15215", "CVE-2019-15218", "CVE-2019-15219", "CVE-2019-15220", "CVE-2019-15221", "CVE-2019-15292", "CVE-2019-15807", "CVE-2019-15917", "CVE-2019-15926", "CVE-2019-9506");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-09-26 02:00:36 +0000 (Thu, 26 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-26 02:00:36 +0000 (Thu, 26 Sep 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1930-1] linux security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00025.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1930-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux'
  package(s) announced via the DSA-1930-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2016-10905

A race condition was discovered in the GFS2 file-system
implementation, which could lead to a use-after-free. On a system
using GFS2, a local attacker could use this for denial of service
(memory corruption or crash) or possibly for privilege escalation.

CVE-2018-20976

It was discovered that the XFS file-system implementation did not
correctly handle some mount failure conditions, which could lead
to a use-after-free. The security impact of this is unclear.

CVE-2018-21008

It was discovered that the rsi wifi driver did not correctly
handle some failure conditions, which could lead to a use-after-
free. The security impact of this is unclear.

CVE-2019-0136

It was discovered that the wifi soft-MAC implementation (mac80211)
did not properly authenticate Tunneled Direct Link Setup (TDLS)
messages. A nearby attacker could use this for denial of service
(loss of wifi connectivity).

CVE-2019-9506

Daniele Antonioli, Nils Ole Tippenhauer, and Kasper Rasmussen
discovered a weakness in the Bluetooth pairing protocols, dubbed
the 'KNOB attack'. An attacker that is nearby during pairing
could use this to weaken the encryption used between the paired
devices, and then to eavesdrop on and/or spoof communication
between them.

This update mitigates the attack by requiring a minimum encryption
key length of 56 bits.

CVE-2019-14814, CVE-2019-14815, CVE-2019-14816

Multiple bugs were discovered in the mwifiex wifi driver, which
could lead to heap buffer overflows. A local user permitted to
configure a device handled by this driver could probably use this
for privilege escalation.

CVE-2019-14821

Matt Delco reported a race condition in KVM's coalesced MMIO
facility, which could lead to out-of-bounds access in the kernel.
A local attacker permitted to access /dev/kvm could use this to
cause a denial of service (memory corruption or crash) or possibly
for privilege escalation.

CVE-2019-14835

Peter Pi of Tencent Blade Team discovered a missing bounds check
in vhost_net, the network back-end driver for KVM hosts, leading
to a buffer overflow when the host begins live migration of a VM.
An attacker in control of a VM could use this to cause a denial of
service (memory corruption or crash) or possibly for privilege
escalation on the host.

CVE-2019-15117

Hui Peng and Mathias Payer reported a missing bounds check in the
usb-audio driver's descriptor parsing code, leading to a buffer
over-read. An attacker able to add USB devices could possibly use
this to cause a deni ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.16.74-1.

We recommend that you upgrade your linux packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.8-arm", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-compiler-gcc-4.9-x86", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.16", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-586", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-686-pae", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-all", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-all-amd64", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-all-armel", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-all-armhf", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-all-i386", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-amd64", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-armmp", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-armmp-lpae", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-common", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-ixp4xx", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-kirkwood", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-orion5x", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.16.0-10-versatile", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-586", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-686-pae", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-686-pae-dbg", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-amd64", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-amd64-dbg", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-armmp", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-armmp-lpae", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-ixp4xx", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-kirkwood", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-orion5x", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.16.0-10-versatile", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.16", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.16", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.16.0-10", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.16.0-10-amd64", ver:"3.16.74-1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);