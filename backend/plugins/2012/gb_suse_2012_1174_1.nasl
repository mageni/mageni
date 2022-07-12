###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1174_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for Security openSUSE-SU-2012:1174-1 (Security)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.850334");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:40 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2012-2625", "CVE-2012-3432", "CVE-2012-3433", "CVE-2012-3494",
                "CVE-2012-3496", "CVE-2012-3515");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for Security openSUSE-SU-2012:1174-1 (Security)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Security'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE11\.4");
  script_tag(name:"affected", value:"Security on openSUSE 11.4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Security Update for Xen

  Following fixes were done:

  - bnc#776995 - attaching scsi control luns with pvscsi

  - xend/pvscsi: fix passing of SCSI control LUNs
  xen-bug776995-pvscsi-no-devname.patch

  - xend/pvscsi: fix usage of persistent device names for
  SCSI devices xen-bug776995-pvscsi-persistent-names.patch

  - xend/pvscsi: update sysfs parser for Linux 3.0
  xen-bug776995-pvscsi-sysfs-parser.patch

  - bnc#777090 - VUL-0: CVE-2012-3494: xen: hypercall
  set_debugreg vulnerability (XSA-12)
  CVE-2012-3494-xsa12.patch

  - bnc#777091 - VUL-0: CVE-2012-3496: xen:
  XENMEM_populate_physmap DoS vulnerability (XSA-14)
  CVE-2012-3496-xsa14.patch

  - bnc#777084 - VUL-0: CVE-2012-3515: xen: Qemu VT100
  emulation vulnerability (XSA-17) CVE-2012-3515-xsa17.patch

  - bnc#744771 - VM with passed through PCI card fails to
  reboot under dom0 load 24888-pci-release-devices.patch

  - Upstream patches from Jan
  25431-x86-EDD-MBR-sig-check.patch
  25459-page-list-splice.patch
  25478-x86-unknown-NMI-deadlock.patch
  25480-x86_64-sysret-canonical.patch
  25481-x86_64-AMD-erratum-121.patch
  25485-x86_64-canonical-checks.patch
  25587-param-parse-limit.patch 25617-vtd-qinval-addr.patch
  25688-x86-nr_irqs_gsi.patch

  - bnc#773393 - VUL-0: CVE-2012-3433: xen: HVM guest destroy
  p2m teardown host DoS vulnerability
  CVE-2012-3433-xsa11.patch

  - bnc#773401 - VUL-1: CVE-2012-3432: xen: HVM guest user
  mode MMIO emulation DoS
  25682-x86-inconsistent-io-state.patch

  - bnc#762484 - VUL-1: CVE-2012-2625: xen: pv bootloader
  doesn't check the size of the bzip2 or lzma compressed
  kernel, leading to denial of service
  25589-pygrub-size-limits.patch");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE11.4")
{

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.0.3_04_k2.6.37.6_0.20~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.0.3_04_k2.6.37.6_0.20~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.0.3_04_k2.6.37.6_0.20~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.0.3_04_k2.6.37.6_0.20~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.0.3_04~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.0.3_04_k2.6.37.6_0.20~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae-debuginfo", rpm:"xen-kmp-pae-debuginfo~4.0.3_04_k2.6.37.6_0.20~45.1", rls:"openSUSE11.4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
