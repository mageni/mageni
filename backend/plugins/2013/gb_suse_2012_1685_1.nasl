###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2012_1685_1.nasl 14114 2019-03-12 11:48:52Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2012:1685-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2012-12/msg00018.html");
  script_oid("1.3.6.1.4.1.25623.1.0.850422");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-11 18:29:53 +0530 (Mon, 11 Mar 2013)");
  script_cve_id("CVE-2012-5510", "CVE-2012-5511", "CVE-2012-5512", "CVE-2012-5513",
                "CVE-2012-5514", "CVE-2012-5515", "CVE-2012-4535", "CVE-2012-4537",
                "CVE-2012-4538", "CVE-2012-4539");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_name("SuSE Update for xen openSUSE-SU-2012:1685-1 (xen)");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE12\.2");
  script_tag(name:"affected", value:"xen on openSUSE 12.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"This update of XEN fixes various denial of service bugs.


  - bnc#789945 - CVE-2012-5510: xen: Grant table version
  switch list corruption vulnerability (XSA-26)

  - bnc#789944 - CVE-2012-5511: xen: Several HVM operations
  do not validate the range of their inputs (XSA-27)

  - bnc#789940 - CVE-2012-5512: xen: HVMOP_get_mem_access
  crash / HVMOP_set_mem_access information leak (XSA-28)

  - bnc#789951 - CVE-2012-5513: xen: XENMEM_exchange may
  overwrite hypervisor memory (XSA-29)

  - bnc#789948 - CVE-2012-5514: xen: Missing unlock in
  guest_physmap_mark_populate_on_demand() (XSA-30)

  - bnc#789950 - CVE-2012-5515: xen: Several memory hypercall
  operations allow invalid extent order values (XSA-31)

  - bnc#789988 - FATAL PAGE FAULT in hypervisor
  (arch_do_domctl)
  25931-x86-domctl-iomem-mapping-checks.patch

  - Upstream patches from Jan
  26132-tmem-save-NULL-check.patch
  26134-x86-shadow-invlpg-check.patch
  26148-vcpu-timer-overflow.patch (Replaces
  CVE-2012-4535-xsa20.patch)
  26149-x86-p2m-physmap-error-path.patch (Replaces
  CVE-2012-4537-xsa22.patch)
  26150-x86-shadow-unhook-toplevel-check.patch (Replaces
  CVE-2012-4538-xsa23.patch)
  26151-gnttab-compat-get-status-frames.patch (Replaces
  CVE-2012-4539-xsa24.patch)


  - bnc#777628 - guest 'disappears' after live migration
  Updated block-dmmd script

  - Fix exception in balloon.py and osdep.py
  xen-max-free-mem.diff

  - bnc#792476 - efi files missing in latest XEN update
  Revert c/s 25751 EFI Makefile changes in
  23614-x86_64-EFI-boot.patch");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE12.2")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.1.3_06_k3.4.11_2.16~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.1.3_06_k3.4.11_2.16~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.1.3_06_k3.4.11_2.16~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.1.3_06_k3.4.11_2.16~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-pdf", rpm:"xen-doc-pdf~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.1.3_06~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.1.3_06_k3.4.11_2.16~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-pae-debuginfo", rpm:"xen-kmp-pae-debuginfo~4.1.3_06_k3.4.11_2.16~5.17.1", rls:"openSUSE12.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
