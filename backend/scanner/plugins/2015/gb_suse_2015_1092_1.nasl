###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_1092_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2015:1092-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850674");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-09-18 10:29:15 +0200 (Fri, 18 Sep 2015)");
  script_cve_id("CVE-2014-3615", "CVE-2015-2044", "CVE-2015-2045", "CVE-2015-2151", "CVE-2015-2152", "CVE-2015-2751", "CVE-2015-2752", "CVE-2015-2756", "CVE-2015-3209", "CVE-2015-3340", "CVE-2015-3456", "CVE-2015-4103", "CVE-2015-4104", "CVE-2015-4105", "CVE-2015-4106", "CVE-2015-4163", "CVE-2015-4164");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen openSUSE-SU-2015:1092-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Xen was updated to 4.4.2 to fix multiple vulnerabilities and non-security
  bugs.

  The following vulnerabilities were fixed:

  * CVE-2015-4103: Potential unintended writes to host MSI message data
  field via qemu (XSA-128) (boo#931625)

  * CVE-2015-4104: PCI MSI mask bits inadvertently exposed to guests
  (XSA-129) (boo#931626)

  * CVE-2015-4105: Guest triggerable qemu MSI-X pass-through error messages
  (XSA-130) (boo#931627)

  * CVE-2015-4106: Unmediated PCI register access in qemu (XSA-131)
  (boo#931628)

  * CVE-2015-4164: DoS through iret hypercall handler (XSA-136) (boo#932996)

  * CVE-2015-4163: GNTTABOP_swap_grant_ref operation misbehavior (XSA-134)
  (boo#932790)

  * CVE-2015-3209: heap overflow in qemu pcnet controller allowing guest to
  host escape (XSA-135) (boo#932770)

  * CVE-2015-3456: Fixed a buffer overflow in the floppy drive emulation,
  which could be used to denial of service attacks or potential code
  execution against the host. ()

  * CVE-2015-3340: Xen did not initialize certain fields, which allowed
  certain remote service domains to obtain sensitive information from
  memory via a (1) XEN_DOMCTL_gettscinfo or (2)
  XEN_SYSCTL_getdomaininfolist request. ()

  * CVE-2015-2752: Long latency MMIO mapping operations are not preemptible
  (XSA-125 boo#922705)

  * CVE-2015-2756: Unmediated PCI command register access in qemu (XSA-126
  boo#922706)

  * CVE-2015-2751: Certain domctl operations may be abused to lock up the
  host (XSA-127 boo#922709)

  * CVE-2015-2151: Hypervisor memory corruption due to x86 emulator flaw
  (boo#919464 XSA-123)

  * CVE-2015-2045: Information leak through version information hypercall
  (boo#918998 XSA-122)

  * CVE-2015-2044: Information leak via internal x86 system device emulation
  (boo#918995 (XSA-121)

  * CVE-2015-2152: HVM qemu unexpectedly enabling emulated VGA graphics
  backends (boo#919663 XSA-119)

  * CVE-2014-3615: information leakage when guest sets high resolution
  (boo#895528)

  The following non-security bugs were fixed:

  * xentop: Fix memory leak on read failure

  * boo#923758: xen dmesg contains bogus output in early boot

  * boo#921842: Xentop doesn't display disk statistics for VMs using qdisks

  * boo#919098: L3: XEN blktap device intermittently fails to connect

  * boo#882089: Windows 2012 R2 fails to boot up with greater than 60 vcpus

  * boo#903680: Problems with detecting free loop devices on Xen guest
  startup

  * boo#861318: xentop reports 'Found interface vif101.0 but domain 101 does
  not exist.'

  * boo#901488: Intel ixgbe driver assigns rx/tx queues per core resulting
  in irq problems on servers with a ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"xen on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.2_06_k3.16.7_21~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.2_06_k3.16.7_21~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.4.2_06_k3.16.7_21~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.4.2_06_k3.16.7_21~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.2_06~23.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}