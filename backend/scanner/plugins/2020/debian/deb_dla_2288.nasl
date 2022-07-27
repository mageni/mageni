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
  script_oid("1.3.6.1.4.1.25623.1.0.892288");
  script_version("2020-07-27T03:00:14+0000");
  script_cve_id("CVE-2017-9503", "CVE-2019-12068", "CVE-2019-20382", "CVE-2020-10756", "CVE-2020-13361", "CVE-2020-13362", "CVE-2020-13659", "CVE-2020-13754", "CVE-2020-13765", "CVE-2020-15863", "CVE-2020-1983", "CVE-2020-8608");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-07-27 03:00:14 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-27 03:00:14 +0000 (Mon, 27 Jul 2020)");
  script_name("Debian LTS: Security Advisory for qemu (DLA-2288-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/07/msg00020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2288-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/865754");
  script_xref(name:"URL", value:"https://bugs.debian.org/961887");
  script_xref(name:"URL", value:"https://bugs.debian.org/961888");
  script_xref(name:"URL", value:"https://bugs.debian.org/964793");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the DLA-2288-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The following CVE(s) were reported against src:qemu:

CVE-2017-9503

QEMU (aka Quick Emulator), when built with MegaRAID SAS 8708EM2
Host Bus Adapter emulation support, allows local guest OS
privileged users to cause a denial of service (NULL pointer
dereference and QEMU process crash) via vectors involving megasas
command processing.

CVE-2019-12068

In QEMU 1:4.1-1 (1:2.8+dfsg-6+deb9u8), when executing script in
lsi_execute_script(), the LSI scsi adapter emulator advances
's->dsp' index to read next opcode. This can lead to an infinite
loop if the next opcode is empty. Move the existing loop exit
after 10k iterations so that it covers no-op opcodes as well.

CVE-2019-20382

QEMU 4.1.0 has a memory leak in zrle_compress_data in
ui/vnc-enc-zrle.c during a VNC disconnect operation because libz
is misused, resulting in a situation where memory allocated in
deflateInit2 is not freed in deflateEnd.

CVE-2020-1983

A use after free vulnerability in ip_reass() in ip_input.c of
libslirp 4.2.0 and prior releases allows crafted packets to cause
a denial of service.

CVE-2020-8608

In libslirp 4.1.0, as used in QEMU 4.2.0, tcp_subr.c misuses
snprintf return values, leading to a buffer overflow in later
code.

CVE-2020-10756

An out-of-bounds read vulnerability was found in the SLiRP
networking implementation of the QEMU emulator. This flaw occurs
in the icmp6_send_echoreply() routine while replying to an ICMP
echo request, also known as ping. This flaw allows a malicious
guest to leak the contents of the host memory, resulting in
possible information disclosure. This flaw affects versions of
libslirp before 4.3.1.

CVE-2020-13361

In QEMU 5.0.0 and earlier, es1370_transfer_audio in
hw/audio/es1370.c does not properly validate the frame count,
which allows guest OS users to trigger an out-of-bounds access
during an es1370_write() operation.

CVE-2020-13362

In QEMU 5.0.0 and earlier, megasas_lookup_frame in
hw/scsi/megasas.c has an out-of-bounds read via a crafted
reply_queue_head field from a guest OS user.

CVE-2020-13659

address_space_map in exec.c in QEMU 4.2.0 can trigger a NULL
pointer dereference related to BounceBuffer.

CVE-2020-13754

hw/pci/msix.c in QEMU 4.2.0 allows guest OS users to trigger
an out-of-bounds access via a crafted address in an msi-x mmio
operation.

CVE-2020-13765

rom_copy() in hw/core/loader.c in QEMU 4.1.0 does not validate
the relationship between two addresses, which allows attackers
to trigger an invalid memory copy operation.

CVE-2020-15863

Stack-based overflow in xgmac_enet_send() in hw/net/xgmac.c.");

  script_tag(name:"affected", value:"'qemu' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1:2.8+dfsg-6+deb9u10.

We recommend that you upgrade your qemu packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"qemu", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-block-extra", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-guest-agent", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-kvm", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-arm", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-common", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-mips", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-misc", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-ppc", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-sparc", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-system-x86", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-binfmt", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-user-static", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"qemu-utils", ver:"1:2.8+dfsg-6+deb9u10", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
