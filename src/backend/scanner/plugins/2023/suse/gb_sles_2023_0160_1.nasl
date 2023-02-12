# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.0160.1");
  script_cve_id("CVE-2021-20251", "CVE-2022-2031", "CVE-2022-32742", "CVE-2022-32744", "CVE-2022-32745", "CVE-2022-32746", "CVE-2022-3437", "CVE-2022-37966", "CVE-2022-37967", "CVE-2022-38023", "CVE-2022-42898");
  script_tag(name:"creation_date", value:"2023-01-27 04:21:47 +0000 (Fri, 27 Jan 2023)");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 20:28:00 +0000 (Thu, 05 Jan 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:0160-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:0160-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20230160-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba' package(s) announced via the SUSE-SU-2023:0160-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for samba fixes the following issues:

CVE-2021-20251: Fixed an issue where the bad password count would not be
 properly incremented, which could allow attackers to brute force a
 user's password (bsc#1206546).

Updated to version 4.15.13:
 - CVE-2022-37966: Fixed an issue where a weak cipher would be selected
 to encrypt session keys, which could lead to privilege escalation
 (bsc#1205385).
 - CVE-2022-37967: Fixed a potential privilege escalation issue via
 constrained delegation due to weak a cryptographic algorithm being
 selected (bsc#1205386).
 - CVE-2022-38023: Disabled weak ciphers by default in the Netlogon
 Secure channel (bsc#1206504).

Updated to version 4.15.12:
 - CVE-2022-42898: Fixed several buffer overflow vulnerabilities on
 32-bit systems (bsc#1205126).

Updated to version 4.15.11:
 - CVE-2022-3437: Fixed a buffer overflow in Heimdal unwrap_des3()
 (bsc#1204254).

Updated to version 4.15.10:
 - Fixed a potential crash due to a concurrency issue (bsc#1200102).

Updated to version 4.15.9:
 - CVE-2022-32742: Fixed an information leak that could be triggered via
 SMB1 (bsc#1201496).
 - CVE-2022-32746: Fixed a memory corruption issue in database audit
 logging (bsc#1201490).
 - CVE-2022-2031: Fixed AD restrictions bypass associated with changing
 passwords (bsc#1201495).
 - CVE-2022-32745: Fixed a remote server crash that could be triggered
 with certain LDAP requests (bsc#1201492).
 - CVE-2022-32744: Fixed an issue where AD users could have forged
 password change requests on behalf of other users (bsc#1201493).

Other fixes:

Fixed a problem when using bind as samba-ad-dc backend related to the
 named service (bsc#1201689).");

  script_tag(name:"affected", value:"'samba' package(s) on SUSE Linux Enterprise High Availability 15-SP4, SUSE Linux Enterprise Micro 5.3, SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

if(release == "SLES15.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-devel", rpm:"libsamba-policy-devel~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy-python3-devel", rpm:"libsamba-policy-python3-devel~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3", rpm:"libsamba-policy0-python3~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsamba-policy0-python3-debuginfo", rpm:"libsamba-policy0-python3-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba", rpm:"samba~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs", rpm:"samba-ad-dc-libs~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ad-dc-libs-debuginfo", rpm:"samba-ad-dc-libs-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph", rpm:"samba-ceph~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ceph-debuginfo", rpm:"samba-ceph-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-debuginfo", rpm:"samba-client-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit", rpm:"samba-client-libs-32bit~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-32bit-debuginfo", rpm:"samba-client-libs-32bit-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs", rpm:"samba-client-libs~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-client-libs-debuginfo", rpm:"samba-client-libs-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-debugsource", rpm:"samba-debugsource~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-devel", rpm:"samba-devel~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules", rpm:"samba-dsdb-modules~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-dsdb-modules-debuginfo", rpm:"samba-dsdb-modules-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-gpupdate", rpm:"samba-gpupdate~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap", rpm:"samba-ldb-ldap~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-ldb-ldap-debuginfo", rpm:"samba-ldb-ldap-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit", rpm:"samba-libs-32bit~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-32bit-debuginfo", rpm:"samba-libs-32bit-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs", rpm:"samba-libs~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-debuginfo", rpm:"samba-libs-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3", rpm:"samba-libs-python3~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-libs-python3-debuginfo", rpm:"samba-libs-python3-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3", rpm:"samba-python3~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-python3-debuginfo", rpm:"samba-python3-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-tool", rpm:"samba-tool~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind", rpm:"samba-winbind~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-debuginfo", rpm:"samba-winbind-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs", rpm:"samba-winbind-libs~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"samba-winbind-libs-debuginfo", rpm:"samba-winbind-libs-debuginfo~4.15.13+git.591.ab36624310c~150400.3.19.1", rls:"SLES15.0SP4"))) {
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
