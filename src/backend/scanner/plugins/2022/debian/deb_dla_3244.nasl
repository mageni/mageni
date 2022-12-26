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
  script_oid("1.3.6.1.4.1.25623.1.0.893244");
  script_version("2022-12-23T02:00:25+0000");
  script_cve_id("CVE-2021-3759", "CVE-2022-3169", "CVE-2022-3435", "CVE-2022-3521", "CVE-2022-3524", "CVE-2022-3564", "CVE-2022-3565", "CVE-2022-3594", "CVE-2022-3628", "CVE-2022-3640", "CVE-2022-3643", "CVE-2022-4139", "CVE-2022-41849", "CVE-2022-41850", "CVE-2022-42328", "CVE-2022-42329", "CVE-2022-42895", "CVE-2022-42896", "CVE-2022-4378", "CVE-2022-47518", "CVE-2022-47519", "CVE-2022-47520", "CVE-2022-47521");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-23 02:00:25 +0000 (Fri, 23 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-23 02:00:25 +0000 (Fri, 23 Dec 2022)");
  script_name("Debian LTS: Security Advisory for linux-5.10 (DLA-3244-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00031.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3244-1");
  script_xref(name:"Advisory-ID", value:"DLA-3244-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1022806");
  script_xref(name:"URL", value:"https://bugs.debian.org/1024697");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-5.10'
  package(s) announced via the DLA-3244-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2021-3759

It was discovered that the memory cgroup controller did not
account for kernel memory allocated for IPC objects. A local user
could use this for denial of service (memory exhaustion).

CVE-2022-3169

It was discovered that the NVMe host driver did not prevent a
concurrent reset and subsystem reset. A local user with access to
an NVMe device could use this to cause a denial of service (device
disconnect or crash).

CVE-2022-3435

Gwangun Jung reported a flaw in the IPv4 forwarding subsystem
which would lead to an out-of-bounds read. A local user with
CAP_NET_ADMIN capability in any user namespace could possibly
exploit this to cause a denial of service (crash).

CVE-2022-3521

The syzbot tool found a race condition in the KCM subsystem
which could lead to a crash.

This subsystem is not enabled in Debian's official kernel
configurations.

CVE-2022-3524

The syzbot tool found a race condition in the IPv6 stack which
could lead to a memory leak. A local user could exploit this to
cause a denial of service (memory exhaustion).

CVE-2022-3564

A flaw was discovered in the Bluetooth L2CAP subsystem which
would lead to a use-after-free. This might be exploitable
to cause a denial of service (crash or memory corruption) or
possibly for privilege escalation.

CVE-2022-3565

A flaw was discovered in the mISDN driver which would lead to a
use-after-free. This might be exploitable to cause a denial of
service (crash or memory corruption) or possibly for privilege
escalation.

CVE-2022-3594

Andrew Gaul reported that the r8152 Ethernet driver would log
excessive numbers of messages in response to network errors. A
remote attacker could possibly exploit this to cause a denial of
service (resource exhaustion).

CVE-2022-3628

Dokyung Song, Jisoo Jang, and Minsuk Kang reported a potential
heap-based buffer overflow in the brcmfmac Wi-Fi driver. A user
able to connect a malicious USB device could exploit this to cause
a denial of service (crash or memory corruption) or possibly for
privilege escalation.

CVE-2022-3640

A flaw was discovered in the Bluetooth L2CAP subsystem which
would lead to a use-after-free. This might be exploitable
to cause a denial of service (crash or memory corruption) or
possibly for privilege escalation.

CVE-2022-3643 (XSA-423)

A flaw was discovered in the Xen network backend driver that would
result in it generating malformed packet buffers. If these
packets were forwarded to certain other network devices, a Xen
guest could exploit this to cau ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-5.10' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
5.10.158-2~deb10u1.

We recommend that you upgrade your linux-5.10 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-686", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-686-pae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-cloud-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-cloud-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-common", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-common-rt", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-686-pae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-686", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-686-pae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-cloud-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-cloud-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-common", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-common-rt", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-686-pae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-686", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-686-pae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-cloud-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-cloud-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-common", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-common-rt", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-rt-686-pae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-rt-amd64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-rt-arm64", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.20-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-signed-template", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-signed-template", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-i386-signed-template", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-pae-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-pae-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-686-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-686-pae-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-686-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-armmp-lpae", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-armmp-lpae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-cloud-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-cloud-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-cloud-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-cloud-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-686-pae-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-686-pae-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-amd64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-amd64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-arm64-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-arm64-unsigned", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-armmp", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.20-rt-armmp-dbg", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.17", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.19", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.20", ver:"5.10.158-2~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
