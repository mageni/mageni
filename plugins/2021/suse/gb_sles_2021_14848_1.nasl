# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14848.1");
  script_cve_id("CVE-2021-0089", "CVE-2021-20255", "CVE-2021-28690", "CVE-2021-28692", "CVE-2021-28697", "CVE-2021-28698", "CVE-2021-28701", "CVE-2021-28703", "CVE-2021-28705", "CVE-2021-28706", "CVE-2021-28709", "CVE-2021-3527", "CVE-2021-3592", "CVE-2021-3594", "CVE-2021-3595", "CVE-2021-3682", "CVE-2021-3930");
  script_tag(name:"creation_date", value:"2021-12-02 03:22:29 +0000 (Thu, 02 Dec 2021)");
  script_version("2021-12-02T03:22:29+0000");
  script_tag(name:"last_modification", value:"2021-12-03 07:32:50 +0000 (Fri, 03 Dec 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-17 17:29:00 +0000 (Tue, 17 Aug 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14848-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14848-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114848-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen' package(s) announced via the SUSE-SU-2021:14848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

CVE-2021-0089: Fixed Speculative Code Store Bypass (XSA-375)
 (bsc#1186433).

CVE-2021-20255: Fixed stack overflow via infinite recursion in eepro100
 (bsc#1182654).

CVE-2021-28690: Fixed x86 TSX Async Abort protections not restored after
 S3 (XSA-377) (bsc#1186434).

CVE-2021-28692: Fixed inappropriate x86 IOMMU timeout detection /
 handling (XSA-373) (bsc#1186429).

CVE-2021-28697: Fixed grant table v2 status pages may remain accessible
 after de-allocation (XSA-379) (bsc#1189376).

CVE-2021-28698: Fixed long running loops in grant table handling.
 (XSA-380) (bsc#1189378).

CVE-2021-28701: Fixed race condition in XENMAPSPACE_grant_table handling
 (XSA-384) (bsc#1189632).

CVE-2021-28703: Fixed grant table v2 status pages may remain accessible
 after de-allocation (take two) (XSA-387) (bsc#1192555).

CVE-2021-28705, CVE-2021-28709: Fixed issues with partially successful
 P2M updates on x86 (XSA-389) (bsc#1192559).

CVE-2021-28706: Fixed guests may exceed their designated memory limit
 (XSA-385) (bsc#1192554).

CVE-2021-3527: Fixed unbounded stack allocation in usbredir
 (bsc#1186013).

CVE-2021-3592: Fixed invalid pointer initialization may lead to
 information disclosure in slirp (bootp) (bsc#1187369).

CVE-2021-3594: Fixed invalid pointer initialization may lead to
 information disclosure in slirp (udp) (bsc#1187378).

CVE-2021-3595: Fixed invalid pointer initialization may lead to
 information disclosure in slirp (tftp) (bsc#1187376).

CVE-2021-3682: Fixed free call on invalid pointer in usbredir bufp_alloc
 (bsc#1189150).

CVE-2021-3930: Fixed off-by-one error in mode_sense_page() in
 hw/scsi/scsi-disk.c (bsc#1192526).");

  script_tag(name:"affected", value:"'xen' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4.");

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

if(release == "SLES11.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.4_50~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.4_50~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.4_50_3.0.101_108.129~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-kmp-pae", rpm:"xen-kmp-pae~4.4.4_50_3.0.101_108.129~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.4_50~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.4_50~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.4_50~61.67.1", rls:"SLES11.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.4_50~61.67.1", rls:"SLES11.0SP4"))) {
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
