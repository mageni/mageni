###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2016_0995_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2016:0995-1 (xen)
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
  script_oid("1.3.6.1.4.1.25623.1.0.851269");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-04-09 05:01:01 +0200 (Sat, 09 Apr 2016)");
  script_cve_id("CVE-2013-4529", "CVE-2013-4530", "CVE-2013-4533", "CVE-2013-4534", "CVE-2013-4537", "CVE-2013-4538", "CVE-2013-4539", "CVE-2014-0222", "CVE-2014-3689", "CVE-2014-7815", "CVE-2014-9718", "CVE-2015-1779", "CVE-2015-5239", "CVE-2015-5278", "CVE-2015-6815", "CVE-2015-6855", "CVE-2015-7512", "CVE-2015-8345", "CVE-2015-8613", "CVE-2015-8619", "CVE-2015-8743", "CVE-2015-8744", "CVE-2015-8745", "CVE-2016-1568", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-1714", "CVE-2016-1981", "CVE-2016-2198", "CVE-2016-2270", "CVE-2016-2271", "CVE-2016-2392", "CVE-2016-2538");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen openSUSE-SU-2016:0995-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"xen was updated to version 4.4.4 to fix 33 security issues.

  These security issues were fixed:

  - CVE-2016-2392: NULL pointer dereference in remote NDIS control message
  handling (bsc#967012).

  - CVE-2015-5239: Integer overflow in vnc_client_read() and
  protocol_client_msg() (bsc#944463).

  - CVE-2016-2270: Xen allowed local guest administrators to cause a denial
  of service (host reboot) via vectors related to multiple mappings of
  MMIO pages with different cachability settings  (boo#965315).

  - CVE-2016-2538: Integer overflow in remote NDIS control message handling
  (bsc#967969).

  - CVE-2015-7512: Buffer overflow in the pcnet_receive function in
  hw/net/pcnet.c, when a guest NIC has a larger MTU, allowed remote
  attackers to cause a denial of service (guest OS crash) or execute
  arbitrary code via a large packet (boo#962360).

  - CVE-2014-3689: The vmware-vga driver (hw/display/vmware_vga.c) allowed
  local guest users to write to qemu memory locations and gain privileges
  via unspecified parameters related to rectangle handling (boo#962611).

  - CVE-2015-5278: Infinite loop in ne2000_receive() function (bsc#945989).

  - CVE-2016-1568: AHCI use-after-free vulnerability in aio port commands
  (bsc#961332).

  - CVE-2016-1981: e1000 infinite loop in start_xmit and e1000_receive_iov
  routines (bsc#963782).

  - CVE-2016-2198: EHCI NULL pointer dereference in ehci_caps_write
  (bsc#964413).

  - CVE-2015-6815: e1000: infinite loop issue (bsc#944697).

  - CVE-2014-0222: Integer overflow in the qcow_open function in
  block/qcow.c allowed remote attackers to cause a denial of service
  (crash) via a large L2 table in a QCOW version 1 image (boo#964925).

  - CVE-2015-6855: hw/ide/core.c did not properly restrict the commands
  accepted by an ATAPI device, which allowed guest users to cause a denial
  of service or possibly have unspecified other impact via certain IDE
  commands, as demonstrated by a WIN_READ_NATIVE_MAX command to an empty
  drive, which triggers a divide-by-zero error and instance crash
  (boo#965156).

  - CVE-2016-2271: VMX in using an Intel or Cyrix CPU, allowed local HVM
  guest users to cause a denial of service (guest crash) via vectors
  related to a non-canonical RIP (boo#965317).

  - CVE-2013-4534: Buffer overflow in hw/intc/openpic.c allowed remote
  attackers to cause a denial of service or possibly execute arbitrary
  code via vectors related to IRQDest elements (boo#964452).

  - CVE-2013-4537: The ssi_sd_transfer function in hw/sd/ssi-sd.c allowed
  remote attackers to execute arbitrary code via a crafted arglen value in
  a savevm image (boo#962642).

  - ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"xen on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_02_k3.16.7_35~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.4_02_k3.16.7_35~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.4.4_02_k3.16.7_35~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.4.4_02_k3.16.7_35~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.4_02~43.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}