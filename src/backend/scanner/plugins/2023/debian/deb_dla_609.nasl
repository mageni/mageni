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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.609");
  script_cve_id("CVE-2016-3857", "CVE-2016-4470", "CVE-2016-5696", "CVE-2016-5829", "CVE-2016-6136", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7118");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-17 21:16:00 +0000 (Tue, 17 Jan 2023)");

  script_name("Debian: Security Advisory (DLA-609)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-609");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-609");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-609 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the CVEs described below.

CVE-2016-3857

Chiachih Wu reported two bugs in the ARM OABI compatibility layer that can be used by local users for privilege escalation. The OABI compatibility layer is enabled in all kernel flavours for armel and armhf.

CVE-2016-4470

Wade Mealing of the Red Hat Product Security Team reported that in some error cases the KEYS subsystem will dereference an uninitialised pointer. A local user can use the keyctl() system call for denial of service (crash) or possibly for privilege escalation.

CVE-2016-5696

Yue Cao, Zhiyun Qian, Zhongjie Wang, Tuan Dao, and Srikanth V. Krishnamurthy of the University of California, Riverside, and Lisa M. Marvel of the United States Army Research Laboratory discovered that Linux's implementation of the TCP Challenge ACK feature results in a side channel that can be used to find TCP connections between specific IP addresses, and to inject messages into those connections.

Where a service is made available through TCP, this may allow remote attackers to impersonate another connected user to the server or to impersonate the server to another connected user. In case the service uses a protocol with message authentication (e.g. TLS or SSH), this vulnerability only allows denial of service (connection failure). An attack takes tens of seconds, so short-lived TCP connections are also unlikely to be vulnerable.

This may be mitigated by increasing the rate limit for TCP Challenge ACKs so that it is never exceeded: sysctl net.ipv4.tcp_challenge_ack_limit=1000000000

CVE-2016-5829

Several heap-based buffer overflow vulnerabilities were found in the hiddev driver, allowing a local user with access to a HID device to cause a denial of service or potentially escalate their privileges.

CVE-2016-6136

Pengfei Wang discovered that the audit subsystem has a 'double-fetch' or TOCTTOU bug in its handling of special characters in the name of an executable. Where audit logging of execve() is enabled, this allows a local user to generate misleading log messages.

CVE-2016-6480

Pengfei Wang discovered that the aacraid driver for Adaptec RAID controllers has a 'double-fetch' or TOCTTOU bug in its validation of FIB messages passed through the ioctl() system call. This has no practical security impact in current Debian releases.

CVE-2016-6828

Marco Grassi reported a 'use-after-free' bug in the TCP implementation, which can be triggered by local users. The security impact is unclear, but might include denial of service or privilege escalation.

CVE-2016-7118

Marcin Szewczyk reported that calling fcntl() on a file descriptor for a directory on an aufs filesystem would result in am oops. This allows local users to cause a denial of service. This is a Debian-specific regression introduced in version 3.2.81-1.

For Debian 7 Wheezy, these problems have been fixed in version 3.2.81-2. This version also fixes a build ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux' package(s) on Debian 7.");

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

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ipv6-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jffs2-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"leds-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armel", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-armhf", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-iop32x", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-ixp4xx", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-kirkwood", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mv78xx0", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-mx5", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-omap", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-orion5x", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-versatile", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-vexpress", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-iop32x", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-ixp4xx", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-kirkwood", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mv78xx0", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-mx5", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-omap", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-orion5x", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-versatile", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-vexpress", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"minix-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mtd-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-kirkwood-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-mx5-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-vexpress-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-486-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-686-pae-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-amd64-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-iop32x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-orion5x-di", ver:"3.2.81-2", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-versatile-di", ver:"3.2.81-2", rls:"DEB7"))) {
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
