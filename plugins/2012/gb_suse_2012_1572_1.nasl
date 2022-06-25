###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1572_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for XEN openSUSE-SU-2012:1572-1 (XEN)
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
  script_oid("1.3.6.1.4.1.25623.1.0.850374");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-12-13 17:01:50 +0530 (Thu, 13 Dec 2012)");
  script_cve_id("CVE-2007-0998", "CVE-2012-2625", "CVE-2012-2934", "CVE-2012-3494",
                "CVE-2012-3495", "CVE-2012-3496", "CVE-2012-3497", "CVE-2012-3498",
                "CVE-2012-3515", "CVE-2012-4411", "CVE-2012-4535", "CVE-2012-4536",
                "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-4544");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for XEN openSUSE-SU-2012:1572-1 (XEN)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'XEN'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.1");
  script_tag(name:"affected", value:"XEN on openSUSE 12.1");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"This security update of XEN fixes various bugs and security
  issues.

  - Upstream patch 26088-xend-xml-filesize-check.patch

  - bnc#787163 - CVE-2012-4544: xen: Domain builder Out-of-
  memory due to malicious kernel/ramdisk (XSA 25)
  CVE-2012-4544-xsa25.patch

  - bnc#779212 - CVE-2012-4411: XEN / qemu: guest
  administrator can access qemu monitor console (XSA-19)
  CVE-2012-4411-xsa19.patch


  - bnc#786516 - CVE-2012-4535: xen: Timer overflow DoS
  vulnerability CVE-2012-4535-xsa20.patch

  - bnc#786518 - CVE-2012-4536: xen: pirq range check DoS
  vulnerability CVE-2012-4536-xsa21.patch

  - bnc#786517 - CVE-2012-4537: xen: Memory mapping failure
  DoS vulnerability CVE-2012-4537-xsa22.patch

  - bnc#786519 - CVE-2012-4538: xen: Unhooking empty PAE
  entries DoS vulnerability CVE-2012-4538-xsa23.patch

  - bnc#786520 - CVE-2012-4539: xen: Grant table hypercall
  infinite loop DoS vulnerability CVE-2012-4539-xsa24.patch

  - bnc#784087 - L3: Xen BUG at io_apic.c:129
  26102-x86-IOAPIC-legacy-not-first.patch

  - Upstream patches from Jan
  26054-x86-AMD-perf-ctr-init.patch
  26055-x86-oprof-hvm-mode.patch
  26056-page-alloc-flush-filter.patch
  26061-x86-oprof-counter-range.patch
  26062-ACPI-ERST-move-data.patch
  26063-x86-HPET-affinity-lock.patch
  26093-HVM-PoD-grant-mem-type.patch

  - Upstream patches from Jan
  25931-x86-domctl-iomem-mapping-checks.patch
  25952-x86-MMIO-remap-permissions.patch

  - Upstream patches from Jan
  25808-domain_create-return-value.patch
  25814-x86_64-set-debugreg-guest.patch
  25815-x86-PoD-no-bug-in-non-translated.patch
  25816-x86-hvm-map-pirq-range-check.patch
  25833-32on64-bogus-pt_base-adjust.patch
  25834-x86-S3-MSI-resume.patch
  25835-adjust-rcu-lock-domain.patch
  25836-VT-d-S3-MSI-resume.patch 25850-tmem-xsa-15-1.patch
  25851-tmem-xsa-15-2.patch 25852-tmem-xsa-15-3.patch
  25853-tmem-xsa-15-4.patch 25854-tmem-xsa-15-5.patch
  25855-tmem-xsa-15-6.patch 25856-tmem-xsa-15-7.patch
  25857-tmem-xsa-15-8.patch 25858-tmem-xsa-15-9.patch
  25859-tmem-missing-break.patch 25860-tmem-cleanup.patch
  25883-pt-MSI-cleanup.patch
  25927-x86-domctl-ioport-mapping-range.patch
  25929-tmem-restore-pool-version.patch

  - bnc#778105 - first XEN-PV VM fails to spawn xend:
  Increase wait time for disk to appear in host bootloader
  Modified existing xen-domUloader.diff

  - Upstream patches from Jan
  25752-ACPI-pm-op-valid-cpu.patch
  25754-x86-PoD-early-access.patch
  25755-x86-PoD-types.patch
  25756-x86-MMIO-max-mapped-pfn.patch
  25757-x86-EPT-PoD-1Gb-assert.patch
  25764-x86-unknown-cpu-no-sysenter.patch
  25765-x86_64-allow-unsafe-adjust.patch
  25771-grant ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.1")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.3_04_k3.1.10_1.16~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.1.3_04_k3.1.10_1.16~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.1.3_04_k3.1.10_1.16~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.1.3_04_k3.1.10_1.16~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-x86", rpm:"xen-libs-debuginfo-x86~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-x86", rpm:"xen-libs-x86~4.1.3_04~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.3_04_k3.1.10_1.16~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae-debuginfo", rpm:"xen-kmp-pae-debuginfo~4.1.3_04_k3.1.10_1.16~1.21.1", rls:"openSUSE12.1")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
