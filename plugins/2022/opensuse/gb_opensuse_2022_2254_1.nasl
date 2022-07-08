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
  script_oid("1.3.6.1.4.1.25623.1.0.854766");
  script_version("2022-07-07T10:16:06+0000");
  script_cve_id("CVE-2021-4206", "CVE-2021-4207", "CVE-2022-26354");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-07-07 10:16:06 +0000 (Thu, 07 Jul 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-10 17:49:00 +0000 (Tue, 10 May 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 01:02:21 +0000 (Tue, 05 Jul 2022)");
  script_name("openSUSE: Security Advisory for qemu (SUSE-SU-2022:2254-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.3");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2254-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/B556HOWMWJ6QWBZWL7YCX63DH5U5A4CW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the SUSE-SU-2022:2254-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

  - CVE-2022-26354: Fixed missing virtqueue detach on error can lead to
       memory leak (bsc#1198712)

  - CVE-2021-4207: Fixed double fetch in qxl_cursor() can lead to heap
       buffer overflow (bsc#1198037)

  - CVE-2021-4206: Fixed integer overflow in cursor_alloc() can lead to heap
       buffer overflow (bsc#1198035)");

  script_tag(name:"affected", value:"'qemu' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa-debuginfo", rpm:"qemu-audio-alsa-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa-debuginfo", rpm:"qemu-audio-pa-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice", rpm:"qemu-audio-spice~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-spice-debuginfo", rpm:"qemu-audio-spice-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-dmg-debuginfo", rpm:"qemu-block-dmg-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster", rpm:"qemu-block-gluster~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-gluster-debuginfo", rpm:"qemu-block-gluster-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs", rpm:"qemu-block-nfs~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-nfs-debuginfo", rpm:"qemu-block-nfs-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-chardev-baum", rpm:"qemu-chardev-baum~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-chardev-baum-debuginfo", rpm:"qemu-chardev-baum-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-chardev-spice", rpm:"qemu-chardev-spice~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-chardev-spice-debuginfo", rpm:"qemu-chardev-spice-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debuginfo", rpm:"qemu-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-extra", rpm:"qemu-extra~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-extra-debuginfo", rpm:"qemu-extra-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-qxl", rpm:"qemu-hw-display-qxl~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-qxl-debuginfo", rpm:"qemu-hw-display-qxl-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu", rpm:"qemu-hw-display-virtio-gpu~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu-debuginfo", rpm:"qemu-hw-display-virtio-gpu-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu-pci", rpm:"qemu-hw-display-virtio-gpu-pci~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-gpu-pci-debuginfo", rpm:"qemu-hw-display-virtio-gpu-pci-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-vga", rpm:"qemu-hw-display-virtio-vga~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-display-virtio-vga-debuginfo", rpm:"qemu-hw-display-virtio-vga-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-s390x-virtio-gpu-ccw", rpm:"qemu-hw-s390x-virtio-gpu-ccw~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-s390x-virtio-gpu-ccw-debuginfo", rpm:"qemu-hw-s390x-virtio-gpu-ccw-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-redirect", rpm:"qemu-hw-usb-redirect~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-redirect-debuginfo", rpm:"qemu-hw-usb-redirect-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-smartcard", rpm:"qemu-hw-usb-smartcard~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-hw-usb-smartcard-debuginfo", rpm:"qemu-hw-usb-smartcard-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ivshmem-tools", rpm:"qemu-ivshmem-tools~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ivshmem-tools-debuginfo", rpm:"qemu-ivshmem-tools-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ksm", rpm:"qemu-ksm~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user", rpm:"qemu-linux-user~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user-debuginfo", rpm:"qemu-linux-user-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-linux-user-debugsource", rpm:"qemu-linux-user-debugsource~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390x", rpm:"qemu-s390x~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390x-debuginfo", rpm:"qemu-s390x-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-testsuite", rpm:"qemu-testsuite~5.2.0~150300.115.4", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses-debuginfo", rpm:"qemu-ui-curses-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk-debuginfo", rpm:"qemu-ui-gtk-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl", rpm:"qemu-ui-opengl~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-opengl-debuginfo", rpm:"qemu-ui-opengl-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app-debuginfo", rpm:"qemu-ui-spice-app-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core", rpm:"qemu-ui-spice-core~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-core-debuginfo", rpm:"qemu-ui-spice-core-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vhost-user-gpu", rpm:"qemu-vhost-user-gpu~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vhost-user-gpu-debuginfo", rpm:"qemu-vhost-user-gpu-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-SLOF", rpm:"qemu-SLOF~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0+~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-microvm", rpm:"qemu-microvm~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.14.0_0_g155821a~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios-8", rpm:"qemu-sgabios-8~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-skiboot", rpm:"qemu-skiboot~5.2.0~150300.115.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.14.0_0_g155821a~150300.115.2", rls:"openSUSELeap15.3"))) {
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