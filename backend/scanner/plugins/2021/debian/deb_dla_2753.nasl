# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892753");
  script_version("2021-09-03T08:01:30+0000");
  script_cve_id("CVE-2021-3527", "CVE-2021-3592", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3682", "CVE-2021-3713");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-09-03 01:00:14 +0000 (Fri, 03 Sep 2021)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-2753-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/09/msg00000.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2753-1");
  script_xref(name:"Advisory-ID", value:"DLA-2753-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/988157");
  script_xref(name:"URL", value:"https://bugs.debian.org/989993");
  script_xref(name:"URL", value:"https://bugs.debian.org/989995");
  script_xref(name:"URL", value:"https://bugs.debian.org/989996");
  script_xref(name:"URL", value:"https://bugs.debian.org/991911");
  script_xref(name:"URL", value:"https://bugs.debian.org/992727");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-2753-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been found in Qemu, a fast processor
emulator.

CVE-2021-3713

An out-of-bounds write flaw was found in the UAS (USB Attached SCSI) device
emulation of QEMU. The device uses the guest supplied stream number
unchecked, which can lead to out-of-bounds access to the UASDevice->data3
and UASDevice->status3 fields. A malicious guest user could use this flaw
to crash QEMU or potentially achieve code execution with the privileges of
the QEMU process on the host.

CVE-2021-3682

A flaw was found in the USB redirector device emulation of QEMU. It occurs
when dropping packets during a bulk transfer from a SPICE client due to the
packet queue being full. A malicious SPICE client could use this flaw to
make QEMU call free() with faked heap chunk metadata, resulting in a crash
of QEMU or potential code execution with the privileges of the QEMU process
on the host.

CVE-2021-3527

A flaw was found in the USB redirector device (usb-redir) of QEMU. Small
USB packets are combined into a single, large transfer request, to reduce
the overhead and improve performance. The combined size of the bulk
transfer is used to dynamically allocate a variable length array (VLA) on
the stack without proper validation. Since the total size is not bounded, a
malicious guest could use this flaw to influence the array length and cause
the QEMU process to perform an excessive allocation on the stack, resulting
in a denial of service.

CVE-2021-3594

An invalid pointer initialization issue was found in the SLiRP networking
implementation of QEMU. The flaw exists in the udp_input() function and
could occur while processing a udp packet that is smaller than the size of
the 'udphdr' structure. This issue may lead to out-of-bounds read access or
indirect host memory disclosure to the guest. The highest threat from this
vulnerability is to data confidentiality.

CVE-2021-3592

An invalid pointer initialization issue was found in the SLiRP networking
implementation of QEMU. The flaw exists in the bootp_input() function and
could occur while processing a udp packet that is smaller than the size of
the 'bootp_t' structure. A malicious guest could use this flaw to leak 10
bytes of uninitialized heap memory from the host. The highest threat from
this vulnerability is to data confidentiality.

CVE-2021-3595

An invalid pointer initialization issue was found in the SLiRP networking
implementation of QEMU. The flaw exists in the tftp_input() function and
could occur while processing a udp packet that is smaller than the size of
the 'tftp_t' structure. This issue may lead to out-of-bounds read access or
indirect host memory disclosure to the guest. The highest threat from this
vulnerability is to data confidentiality.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u15.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.8+dfsg-6+deb9u15", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
