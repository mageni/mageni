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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2014.0015");
  script_cve_id("CVE-2013-4387", "CVE-2013-4470", "CVE-2014-0203", "CVE-2014-2678", "CVE-2014-3122", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3917", "CVE-2014-4652", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 18:03:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Debian: Security Advisory (DLA-0015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB6");

  script_xref(name:"Advisory-ID", value:"DLA-0015");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2014/dla-0015");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-2.6' package(s) announced via the DLA-0015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes several remote and local denial of service attacks and other issues:

CVE-2013-4387: ipv6: udp packets following an UFO enqueued packet need also be handled by UFO to prevent remote attackers to cause a denial of service (memory corruption and system crash) or possibly have unspecified other impact via network traffic that triggers a large response packet.

CVE-2013-4470: inet: fix possible memory corruption with UDP_CORK and UFO to prevent local users to cause a denial of service (memory corruption and system crash) or possibly gain privileges via a crafted application.

CVE-2014-0203: fix autofs/afs/etc. magic mountpoint breakage, preventing denial of service attacks by local users.

CVE-2014-2678: rds: prevent dereference of a NULL device in rds_iw_laddr_check to prevent local denial of service attacks (system crash or possibly have unspecified other impact).

CVE-2014-3122

: Incorrect locking of memory can result in local denial of service.

CVE-2014-3144

/ CVE-2014-3145: A local user can cause a denial of service (system crash) via crafted BPF instructions.

CVE-2014-3917: auditsc: audit_krule mask accesses need bounds checking to prevent a local denial of service attack (OOPS) or possibly leaking sensitive single-bit values from kernel memory.

CVE-2014-4652: ALSA: control: Protect user controls against concurrent access, resulting in a race condition, possibly allowing local users access to sensitive information from kernel memory.

CVE-2014-4656: ALSA: control: Make sure that id->index does not overflow, to prevent a denial of service of the sound system by local users.

CVE-2014-4667: sctp: Fix sk_ack_backlog wrap-around problem, preventing denial of service (socket outage) via a crafted SCTP packet by remote attackers.

CVE-2014-4699: Andy Lutomirski discovered that the ptrace syscall was not verifying the RIP register to be valid in the ptrace API on x86_64 processors. An unprivileged user could use this flaw to crash the kernel (resulting in denial of service) or for privilege escalation.

For Debian 6 Squeeze, these issues have been fixed in linux-2.6 version 2.6.32-48squeeze8");

  script_tag(name:"affected", value:"'linux-2.6' package(s) on Debian 6.");

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

if(release == "DEB6") {

  if(!isnull(res = isdpkgvuln(pkg:"firmware-linux-free", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-base", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-2.6.32", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-486", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all-i386", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-all", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-openvz", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-vserver", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common-xen", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-common", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-486", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686-bigmem", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-openvz-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686-bigmem", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-vserver-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64-dbg", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-2.6.32", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-patch-debian-2.6.32", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-2.6.32", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-2.6.32-5", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-tools-2.6.32", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-686", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-2.6.32-5-xen-amd64", ver:"2.6.32-48squeeze8", rls:"DEB6"))) {
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
