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
  script_oid("1.3.6.1.4.1.25623.1.0.893173");
  script_version("2022-11-09T08:42:14+0000");
  script_cve_id("CVE-2021-4037", "CVE-2022-0171", "CVE-2022-1184", "CVE-2022-1679", "CVE-2022-20421", "CVE-2022-20422", "CVE-2022-2153", "CVE-2022-2602", "CVE-2022-2663", "CVE-2022-2905", "CVE-2022-3028", "CVE-2022-3061", "CVE-2022-3176", "CVE-2022-3303", "CVE-2022-3586", "CVE-2022-3621", "CVE-2022-3625", "CVE-2022-3629", "CVE-2022-3633", "CVE-2022-3635", "CVE-2022-3646", "CVE-2022-3649", "CVE-2022-39188", "CVE-2022-39190", "CVE-2022-39842", "CVE-2022-40307", "CVE-2022-41222", "CVE-2022-41674", "CVE-2022-42719", "CVE-2022-42720", "CVE-2022-42721", "CVE-2022-42722", "CVE-2022-43750");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-11-09 08:42:14 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-24 22:22:00 +0000 (Tue, 24 May 2022)");
  script_tag(name:"creation_date", value:"2022-11-02 02:00:32 +0000 (Wed, 02 Nov 2022)");
  script_name("Debian LTS: Security Advisory for linux-5.10 (DLA-3173-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/11/msg00001.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3173-1");
  script_xref(name:"Advisory-ID", value:"DLA-3173-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1017425");
  script_xref(name:"URL", value:"https://bugs.debian.org/1019248");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-5.10'
  package(s) announced via the DLA-3173-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that
may lead to a privilege escalation, denial of service or information
leaks.

CVE-2021-4037

Christian Brauner reported that the inode_init_owner function for
the XFS filesystem in the Linux kernel allows local users to
create files with an unintended group ownership allowing attackers
to escalate privileges by making a plain file executable and SGID.

CVE-2022-0171

Mingwei Zhang reported that a cache incoherence issue in the SEV
API in the KVM subsystem may result in denial of service.

CVE-2022-1184

A flaw was discovered in the ext4 filesystem driver which can lead
to a use-after-free. A local user permitted to mount arbitrary
filesystems could exploit this to cause a denial of service (crash
or memory corruption) or possibly for privilege escalation.

CVE-2022-1679

The syzbot tool found a race condition in the ath9k_htc driver
which can lead to a use-after-free. This might be exploitable to
cause a denial service (crash or memory corruption) or possibly
for privilege escalation.

CVE-2022-2153

'kangel' reported a flaw in the KVM implementation for x86
processors which could lead to a null pointer dereference. A local
user permitted to access /dev/kvm could exploit this to cause a
denial of service (crash).

CVE-2022-2602

A race between handling an io_uring request and the Unix socket
garbage collector was discovered. An attacker can take advantage
of this flaw for local privilege escalation.

CVE-2022-2663

David Leadbeater reported flaws in the nf_conntrack_irc
connection-tracking protocol module. When this module is enabled
on a firewall, an external user on the same IRC network as an
internal user could exploit its lax parsing to open arbitrary TCP
ports in the firewall, to reveal their public IP address, or to
block their IRC connection at the firewall.

CVE-2022-2905

Hsin-Wei Hung reported a flaw in the eBPF verifier which can lead
to an out-of-bounds read. If unprivileged use of eBPF is enabled,
this could leak sensitive information. This was already disabled
by default, which would fully mitigate the vulnerability.

CVE-2022-3028

Abhishek Shah reported a race condition in the AF_KEY subsystem,
which could lead to an out-of-bounds write or read. A local user
could exploit this to cause a denial of service (crash or memory
corruption), to obtain sensitive information, or possibly for
privilege escalation.

CVE-2022-3061

A flaw was discovered in the i740 driver which may result in
denial of service.

This driver is not enabled in Debian's official kernel
configurations.

CVE-2022-3176

A use-after-free flaw was discovered in the i ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'linux-5.10' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
5.10.149-2~deb10u1. This update also fixes a regression for some
older 32-bit PCs (bug #1017425), and enables the i10nm_edac driver
(bug #1019248). It additionally includes many more bug fixes from
stable updates 5.10.137-5.10.149 inclusive.

We recommend that you upgrade your linux-5.10 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"linux-config-5.10", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-armmp-lpae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10-rt-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-686", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-686-pae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-amd64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-arm64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-armmp-lpae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-cloud-amd64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-cloud-arm64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-common", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-common-rt", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-686-pae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-amd64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-arm64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.17-rt-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-686", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-686-pae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-amd64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-arm64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-armmp-lpae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-cloud-amd64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-cloud-arm64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-common", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-common-rt", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-686-pae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-amd64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-arm64", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.19-rt-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-686-pae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-amd64-signed-template", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-arm64-signed-template", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-armmp-lpae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-cloud-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-i386-signed-template", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-686-pae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10-rt-armmp-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-pae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-pae-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-686-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-amd64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-arm64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-lpae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-armmp-lpae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-amd64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-cloud-arm64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-686-pae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-686-pae-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-amd64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-arm64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.17-rt-armmp-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-pae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-pae-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-686-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-amd64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-arm64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp-lpae", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-armmp-lpae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-amd64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-cloud-arm64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-686-pae-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-686-pae-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-amd64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-amd64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-arm64-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-arm64-unsigned", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-armmp", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.10.0-0.deb10.19-rt-armmp-dbg", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-kbuild-5.10", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-perf-5.10", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.17", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.19", ver:"5.10.149-2~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
