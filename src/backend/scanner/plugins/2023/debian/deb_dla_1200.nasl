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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2017.1200");
  script_cve_id("CVE-2016-10208", "CVE-2017-1000407", "CVE-2017-12190", "CVE-2017-13080", "CVE-2017-14051", "CVE-2017-15115", "CVE-2017-15265", "CVE-2017-15299", "CVE-2017-15649", "CVE-2017-15868", "CVE-2017-16525", "CVE-2017-16527", "CVE-2017-16529", "CVE-2017-16531", "CVE-2017-16532", "CVE-2017-16533", "CVE-2017-16535", "CVE-2017-16536", "CVE-2017-16537", "CVE-2017-16643", "CVE-2017-16649", "CVE-2017-16939", "CVE-2017-8824", "CVE-2017-8831");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-24 18:32:00 +0000 (Fri, 24 Feb 2023)");

  script_name("Debian: Security Advisory (DLA-1200)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-1200");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2017/dla-1200");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux' package(s) announced via the DLA-1200 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2016-10208

Sergej Schumilo and Ralf Spenneberg discovered that a crafted ext4 filesystem could trigger memory corruption when it is mounted. A user that can provide a device or filesystem image to be mounted could use this for denial of service (crash or data corruption) or possibly for privilege escalation.

CVE-2017-8824

Mohamed Ghannam discovered that the DCCP implementation did not correctly manage resources when a socket is disconnected and reconnected, potentially leading to a use-after-free. A local user could use this for denial of service (crash or data corruption) or possibly for privilege escalation. On systems that do not already have the dccp module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-dccp.conf install dccp false

CVE-2017-8831

Pengfei Wang discovered that the saa7164 video capture driver re-reads data from a PCI device after validating it. A physically present user able to attach a specially designed PCI device could use this for privilege escalation.

CVE-2017-12190

Vitaly Mayatskikh discovered that the block layer did not correctly count page references for raw I/O from user-space. This can be exploited by a guest VM with access to a host SCSI device for denial of service (memory exhaustion) or potentially for privilege escalation.

CVE-2017-13080

A vulnerability was found in the WPA2 protocol that could lead to reinstallation of the same Group Temporal Key (GTK), which substantially reduces the security of wifi encryption. This is one of the issues collectively known as KRACK.

Updates to GTKs are usually handled by the wpa package, where this issue was already fixed (DLA-1150-1). However, some wifi devices can remain active and update GTKs autonomously while the system is suspended. The kernel must also check for and ignore key reinstallation.

CVE-2017-14051

shqking reported that the qla2xxx SCSI host driver did not correctly validate I/O to the optrom sysfs attribute of the devices it creates. This is unlikely to have any security impact.

CVE-2017-15115

Vladis Dronov reported that the SCTP implementation did not correctly handle 'peel-off' of an association to another net namespace. This leads to a use-after-free, which a local user can exploit for denial of service (crash or data corruption) or possibly for privilege escalation. On systems that do not already have the sctp module loaded, this can be mitigated by disabling it: echo >> /etc/modprobe.d/disable-sctp.conf install sctp false

CVE-2017-15265

Michael23 Yu reported a race condition in the ALSA sequencer subsystem involving creation and deletion of ports, which could lead to a use-after-free. A local user with access to an ALSA sequencer device can use this for denial of service (crash or data ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"acpi-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ata-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"btrfs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"cdrom-core-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"core-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crc-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-dm-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"crypto-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"efi-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"event-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext2-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext3-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ext4-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fat-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fb-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"firewire-core-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"floppy-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"fuse-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"hyperv-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"i2c-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"input-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"irda-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"isofs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jfs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"kernel-image-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-3.2", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-486", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-686-pae", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-amd64", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all-i386", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-all", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-amd64", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common-rt", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-common", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-686-pae", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-3.2.0-4-rt-amd64", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-486", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae-dbg", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-686-pae", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64-dbg", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-amd64", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae-dbg", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-686-pae", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64-dbg", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-3.2.0-4-rt-amd64", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-libc-dev", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-manual-3.2", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-3.2", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-3.2.0-4", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"loop-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"md-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-core-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mmc-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"mouse-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"multipath-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nbd-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-extra-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-shared-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-usb-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nic-wireless-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ntfs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"parport-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pata-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"pcmcia-storage-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"plip-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ppp-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"qnx4-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"reiserfs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sata-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-common-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-core-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-extra-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"scsi-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"serial-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sound-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"speakup-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"squashfs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"udf-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ufs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"uinput-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-serial-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"usb-storage-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"virtio-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-686-pae", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-linux-system-3.2.0-4-amd64", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xfs-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-486-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-686-pae-di", ver:"3.2.96-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"zlib-modules-3.2.0-4-amd64-di", ver:"3.2.96-1", rls:"DEB7"))) {
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
