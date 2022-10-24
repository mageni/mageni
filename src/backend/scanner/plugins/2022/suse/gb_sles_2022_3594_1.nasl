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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3594.1");
  script_cve_id("CVE-2020-17380", "CVE-2020-25085", "CVE-2021-3409", "CVE-2021-4206", "CVE-2021-4207", "CVE-2022-0216", "CVE-2022-35414");
  script_tag(name:"creation_date", value:"2022-10-17 12:10:44 +0000 (Mon, 17 Oct 2022)");
  script_version("2022-10-18T10:13:37+0000");
  script_tag(name:"last_modification", value:"2022-10-18 10:13:37 +0000 (Tue, 18 Oct 2022)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-18 14:08:00 +0000 (Mon, 18 Jul 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3594-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3594-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223594-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu' package(s) announced via the SUSE-SU-2022:3594-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for qemu fixes the following issues:

CVE-2021-3409: Fixed an incomplete fix for CVE-2020-17380 and
 CVE-2020-25085 in sdhi controller. (bsc#1182282)

CVE-2021-4206: Fixed an integer overflow in cursor_alloc which can lead
 to heap buffer overflow. (bsc#1198035)

CVE-2021-4207: Fixed a double fetch in qxl_cursor ehich can lead to heap
 buffer overflow. (bsc#1198037)

CVE-2022-0216: Fixed a use after free issue found in
 hw/scsi/lsi53c895a.c. (bsc#1198038)

CVE-2022-35414: Fixed an uninitialized read during address translation
 that leads to a crash. (bsc#1201367)");

  script_tag(name:"affected", value:"'qemu' package(s) on SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"qemu", rpm:"qemu~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa", rpm:"qemu-audio-alsa~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-alsa-debuginfo", rpm:"qemu-audio-alsa-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa", rpm:"qemu-audio-pa~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-audio-pa-debuginfo", rpm:"qemu-audio-pa-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debuginfo", rpm:"qemu-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0+~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-microvm", rpm:"qemu-microvm~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.12.1+~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-sgabios", rpm:"qemu-sgabios~8~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses", rpm:"qemu-ui-curses~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-curses-debuginfo", rpm:"qemu-ui-curses-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk", rpm:"qemu-ui-gtk~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-gtk-debuginfo", rpm:"qemu-ui-gtk-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app", rpm:"qemu-ui-spice-app~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-ui-spice-app-debuginfo", rpm:"qemu-ui-spice-app-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.12.1+~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~4.2.1~150200.69.1", rls:"SLES15.0SP2"))) {
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
