###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_1560_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for qemu SUSE-SU-2016:1560-1 (qemu)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851335");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-06-14 05:25:47 +0200 (Tue, 14 Jun 2016)");
  script_cve_id("CVE-2014-3615", "CVE-2014-3689", "CVE-2014-9718", "CVE-2015-3214",
                "CVE-2015-5239", "CVE-2015-5745", "CVE-2015-7295", "CVE-2015-7549",
                "CVE-2015-8504", "CVE-2015-8558", "CVE-2015-8567", "CVE-2015-8568",
                "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744",
                "CVE-2015-8745", "CVE-2015-8817", "CVE-2015-8818", "CVE-2016-1568",
                "CVE-2016-1714", "CVE-2016-1922", "CVE-2016-1981", "CVE-2016-2198",
                "CVE-2016-2538", "CVE-2016-2841", "CVE-2016-2857", "CVE-2016-2858",
                "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-4001", "CVE-2016-4002",
                "CVE-2016-4020", "CVE-2016-4037", "CVE-2016-4439", "CVE-2016-4441",
                "CVE-2016-4952");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for qemu SUSE-SU-2016:1560-1 (qemu)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'qemu'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"qemu was updated to fix 37 security issues.

  These security issues were fixed:

  - CVE-2016-4439: Avoid OOB access in 53C9X emulation (bsc#980711)

  - CVE-2016-4441: Avoid OOB access in 53C9X emulation (bsc#980723)

  - CVE-2016-4952: Avoid OOB access in Vmware PV SCSI emulation (bsc#981266)

  - CVE-2015-8817: Avoid OOB access in PCI DMA I/O (bsc#969121)

  - CVE-2015-8818: Avoid OOB access in PCI DMA I/O (bsc#969122)

  - CVE-2016-3710: Fixed VGA emulation based OOB access with potential for
  guest escape (bsc#978158)

  - CVE-2016-3712: Fixed VGa emulation based DOS and OOB read access exploit
  (bsc#978160)

  - CVE-2016-4037: Fixed USB ehci based DOS (bsc#976109)

  - CVE-2016-2538: Fixed potential OOB access in USB net device emulation
  (bsc#967969)

  - CVE-2016-2841: Fixed OOB access / hang in ne2000 emulation (bsc#969350)

  - CVE-2016-2858: Avoid potential DOS when using QEMU pseudo random number
  generator (bsc#970036)

  - CVE-2016-2857: Fixed OOB access when processing IP checksums (bsc#970037)

  - CVE-2016-4001: Fixed OOB access in Stellaris enet emulated nic
  (bsc#975128)

  - CVE-2016-4002: Fixed OOB access in MIPSnet emulated controller
  (bsc#975136)

  - CVE-2016-4020: Fixed possible host data leakage to guest from TPR access
  (bsc#975700)

  - CVE-2015-3214: Fixed OOB read in i8254 PIC (bsc#934069)

  - CVE-2014-9718: Fixed the handling of malformed or short ide PRDTs to
  avoid any opportunity for guest to cause DoS by abusing that interface
  (bsc#928393)

  - CVE-2014-3689: Fixed insufficient parameter validation in rectangle
  functions (bsc#901508)

  - CVE-2014-3615: The VGA emulator in QEMU allowed local guest users to
  read host memory by setting the display to a high resolution
  (bsc#895528).

  - CVE-2015-5239: Integer overflow in vnc_client_read() and
  protocol_client_msg() (bsc#944463).

  - CVE-2015-5745: Buffer overflow in virtio-serial (bsc#940929).

  - CVE-2015-7295: hw/virtio/virtio.c in the Virtual Network Device
  (virtio-net) support in QEMU, when big or mergeable receive buffers are
  not supported, allowed remote attackers to cause a denial of service
  (guest network consumption) via a flood of jumbo frames on the (1)
  tuntap or (2) macvtap interface (bsc#947159).

  - CVE-2015-7549: PCI null pointer dereferences (bsc#958917).

  - CVE-2015-8504: VNC floating point exception (bsc#958491).

  - CVE-2015-8558: Infinite loop in ehci_advance_state resulting in DoS
  (bsc#959005).

  - CVE-2015-8567: A guest repeatedly activating a vmxnet3 device can leak
  host memory (bsc#959386).

  - CVE-2015-8568: A guest repe ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"qemu on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Desktop 12");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(SLED12\.0SP0|SLES12\.0SP0)");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "SLED12.0SP0")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~2.0.2~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.7.4~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-sgabios-8", rpm:"qemu-sgabios-8~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.7.4~48.19.1", rls:"SLED12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "SLES12.0SP0")
{

  if ((res = isrpmvuln(pkg:"qemu", rpm:"qemu~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl", rpm:"qemu-block-curl~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-curl-debuginfo", rpm:"qemu-block-curl-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-debugsource", rpm:"qemu-debugsource~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent", rpm:"qemu-guest-agent~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-guest-agent-debuginfo", rpm:"qemu-guest-agent-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-lang", rpm:"qemu-lang~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools", rpm:"qemu-tools~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-tools-debuginfo", rpm:"qemu-tools-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-kvm", rpm:"qemu-kvm~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ppc", rpm:"qemu-ppc~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ppc-debuginfo", rpm:"qemu-ppc-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-rbd", rpm:"qemu-block-rbd~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-block-rbd-debuginfo", rpm:"qemu-block-rbd-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86", rpm:"qemu-x86~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-x86-debuginfo", rpm:"qemu-x86-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-ipxe", rpm:"qemu-ipxe~1.0.0~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-seabios", rpm:"qemu-seabios~1.7.4~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-sgabios-8", rpm:"qemu-sgabios-8~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-vgabios", rpm:"qemu-vgabios~1.7.4~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-s390", rpm:"qemu-s390~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"qemu-s390-debuginfo", rpm:"qemu-s390-debuginfo~2.0.2~48.19.1", rls:"SLES12.0SP0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
