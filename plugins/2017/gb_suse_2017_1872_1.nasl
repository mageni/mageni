###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_1872_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for qemu openSUSE-SU-2017:1872-1 (qemu)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.851580");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-07-16 07:22:49 +0200 (Sun, 16 Jul 2017)");
  script_cve_id("CVE-2016-10028", "CVE-2016-10029", "CVE-2016-9602", "CVE-2016-9603",
                "CVE-2017-5579", "CVE-2017-5973", "CVE-2017-5987", "CVE-2017-6505",
                "CVE-2017-7377", "CVE-2017-7471", "CVE-2017-7493", "CVE-2017-7718",
                "CVE-2017-7980", "CVE-2017-8086", "CVE-2017-8112", "CVE-2017-8309",
                "CVE-2017-8379", "CVE-2017-8380", "CVE-2017-9330", "CVE-2017-9373",
                "CVE-2017-9374", "CVE-2017-9375", "CVE-2017-9503");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for qemu openSUSE-SU-2017:1872-1 (qemu)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for qemu fixes several issues.

  These security issues were fixed:

  - CVE-2017-9330: USB OHCI Emulation in qemu allowed local guest OS users
  to cause a denial of service (infinite loop) by leveraging an incorrect
  return value (bsc#1042159).

  - CVE-2017-8379: Memory leak in the keyboard input event handlers support
  allowed local guest OS privileged users to cause a denial of service
  (host memory consumption) by rapidly generating large keyboard events
  (bsc#1037334).

  - CVE-2017-8309: Memory leak in the audio/audio.c allowed remote attackers
  to cause a denial of service (memory consumption) by repeatedly starting
  and stopping audio capture (bsc#1037242).

  - CVE-2017-7493: The VirtFS, host directory sharing via Plan 9 File
  System(9pfs) support, was vulnerable to an improper access control
  issue. It could occur while accessing virtfs metadata files in
  mapped-file security mode. A guest user could have used this flaw to
  escalate their privileges inside guest (bsc#1039495).

  - CVE-2017-7377: The v9fs_create and v9fs_lcreate functions in
  hw/9pfs/9p.c allowed local guest OS privileged users to cause a denial
  of service (file descriptor or memory consumption) via vectors related
  to an already in-use fid (bsc#1032075).

  - CVE-2017-8086: A memory leak in the v9fs_list_xattr function in
  hw/9pfs/9p-xattr.c allowed local guest OS privileged users to cause a
  denial of service (memory consumption) via vectors involving the
  orig_value variable (bsc#1035950).

  - CVE-2017-5973: A infinite loop while doing control transfer in
  xhci_kick_epctx allowed privileged user inside the guest to crash the
  host process resulting in DoS (bsc#1025109)

  - CVE-2017-5987: The sdhci_sdma_transfer_multi_blocks function in
  hw/sd/sdhci.c allowed local OS guest privileged users to cause a denial
  of service (infinite loop and QEMU process crash) via vectors involving
  the transfer mode register during multi block transfer (bsc#1025311).

  - CVE-2017-6505: The ohci_service_ed_list function in hw/usb/hcd-ohci.c
  allowed local guest OS users to cause a denial of service (infinite
  loop) via vectors involving the number of link endpoint list descriptors
  (bsc#1028184)

  - CVE-2016-9603: A privileged user within the guest VM could have caused a
  heap overflow in the device model process, potentially escalating their
  privileges to that of the device model process (bsc#1028656)

  - CVE-2017-7718: hw/display/cirrus_vga_rop.h allowed local guest OS
  privileged users to cause a denial of service (out-of-bounds read and
  QEMU process crash) via vectors related to copy ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"qemu on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-arm", rpm:"qemu-arm~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-arm-debuginfo", rpm:"qemu-arm-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-dmg", rpm:"qemu-block-dmg~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-dmg-debuginfo", rpm:"qemu-block-dmg-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-iscsi", rpm:"qemu-block-iscsi~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-iscsi-debuginfo", rpm:"qemu-block-iscsi-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-ssh", rpm:"qemu-block-ssh~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-ssh-debuginfo", rpm:"qemu-block-ssh-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-extra", rpm:"qemu-extra~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-extra-debuginfo", rpm:"qemu-extra-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-linux-user", rpm:"qemu-linux-user~2.6.2~31.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-linux-user-debuginfo", rpm:"qemu-linux-user-debuginfo~2.6.2~31.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-linux-user-debugsource", rpm:"qemu-linux-user-debugsource~2.6.2~31.3.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-testsuite", rpm:"qemu-testsuite~2.6.2~31.3.6", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~2.6.2~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.9.1~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-sgabios-8", rpm:"qemu-sgabios-8~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.9.1~31.3.3", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
