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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.2919.1");
  script_cve_id("CVE-2022-2509");
  script_tag(name:"creation_date", value:"2022-08-29 04:54:21 +0000 (Mon, 29 Aug 2022)");
  script_version("2022-08-29T04:54:21+0000");
  script_tag(name:"last_modification", value:"2022-08-29 04:54:21 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-05 21:49:00 +0000 (Fri, 05 Aug 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:2919-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP4)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2919-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20222919-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnutls' package(s) announced via the SUSE-SU-2022:2919-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gnutls fixes the following issues:

CVE-2022-2509: Fixed a double free issue during PKCS7 verification
 (bsc#1202020).

Non-security fixes:

FIPS: Check minimum keylength for symmetric key generation [bsc#1190698]

FIPS: Only allows ECDSA signature with valid set of hashes (SHA2 and
 SHA3) [bsc#1190698]

FIPS: Provides interface for running library self tests on-demand
 [bsc#1198979]");

  script_tag(name:"affected", value:"'gnutls' package(s) on SUSE Linux Enterprise Module for Basesystem 15-SP4.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnutls", rpm:"gnutls~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debuginfo", rpm:"gnutls-debuginfo~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnutls-debugsource", rpm:"gnutls-debugsource~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls-devel", rpm:"libgnutls-devel~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30", rpm:"libgnutls30~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit", rpm:"libgnutls30-32bit~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-32bit-debuginfo", rpm:"libgnutls30-32bit-debuginfo~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-debuginfo", rpm:"libgnutls30-debuginfo~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac", rpm:"libgnutls30-hmac~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutls30-hmac-32bit", rpm:"libgnutls30-hmac-32bit~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx-devel", rpm:"libgnutlsxx-devel~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28", rpm:"libgnutlsxx28~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgnutlsxx28-debuginfo", rpm:"libgnutlsxx28-debuginfo~3.7.3~150400.4.10.1", rls:"SLES15.0SP4"))) {
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
