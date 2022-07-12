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
  script_oid("1.3.6.1.4.1.25623.1.0.891927");
  script_version("2019-09-21T02:00:23+0000");
  script_cve_id("CVE-2016-5126", "CVE-2016-5403", "CVE-2017-9375", "CVE-2019-12068", "CVE-2019-12155", "CVE-2019-13164", "CVE-2019-14378", "CVE-2019-15890");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-21 02:00:23 +0000 (Sat, 21 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-21 02:00:23 +0000 (Sat, 21 Sep 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1927-1] qemu security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/09/msg00021.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1927-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/826151");
  script_xref(name:"URL", value:"https://bugs.debian.org/832619");
  script_xref(name:"URL", value:"https://bugs.debian.org/864219");
  script_xref(name:"URL", value:"https://bugs.debian.org/929353");
  script_xref(name:"URL", value:"https://bugs.debian.org/931351");
  script_xref(name:"URL", value:"https://bugs.debian.org/933741");
  script_xref(name:"URL", value:"https://bugs.debian.org/933742");
  script_xref(name:"URL", value:"https://bugs.debian.org/939868");
  script_xref(name:"URL", value:"https://bugs.debian.org/939869");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DSA-1927-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were found in QEMU, a fast processor emulator
(notably used in KVM and Xen HVM virtualization).

CVE-2016-5126

Heap-based buffer overflow in the iscsi_aio_ioctl function in
block/iscsi.c in QEMU allows local guest OS users to cause a
denial of service (QEMU process crash) or possibly execute
arbitrary code via a crafted iSCSI asynchronous I/O ioctl call.

CVE-2016-5403

The virtqueue_pop function in hw/virtio/virtio.c in QEMU allows
local guest OS administrators to cause a denial of service (memory
consumption and QEMU process crash) by submitting requests without
waiting for completion.

CVE-2017-9375

QEMU, when built with USB xHCI controller emulator support, allows
local guest OS privileged users to cause a denial of service
(infinite recursive call) via vectors involving control transfer
descriptors sequencing.

CVE-2019-12068

QEMU scsi disk backend: lsi: exit infinite loop while executing
script

CVE-2019-12155

interface_release_resource in hw/display/qxl.c in QEMU has a NULL
pointer dereference.

CVE-2019-13164

qemu-bridge-helper.c in QEMU does not ensure that a network
interface name (obtained from bridge.conf or a --br=bridge option)
is limited to the IFNAMSIZ size, which can lead to an ACL bypass.

CVE-2019-14378

ip_reass in ip_input.c in libslirp 4.0.0 has a heap-based buffer
overflow via a large packet because it mishandles a case involving
the first fragment.

CVE-2019-15890

libslirp 4.0.0, as used in QEMU, has a use-after-free in ip_reass
in ip_input.c.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
1:2.1+dfsg-12+deb8u12.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.1+dfsg-12+deb8u12", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);