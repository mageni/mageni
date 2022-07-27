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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.14700.1");
  script_cve_id("CVE-2020-36221", "CVE-2020-36222", "CVE-2020-36223", "CVE-2020-36224", "CVE-2020-36225", "CVE-2020-36226", "CVE-2020-36227", "CVE-2020-36228", "CVE-2020-36229", "CVE-2020-36230", "CVE-2021-27212");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:40 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:30:01+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-05-26 19:15:00 +0000 (Wed, 26 May 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:14700-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES11\.0SP4|SLES11\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:14700-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-202114700-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openldap2' package(s) announced via the SUSE-SU-2021:14700-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for openldap2 fixes the following issues:

bsc#1182408 CVE-2020-36230 - an assertion failure in slapd in the X.509
 DN parsing in decode.c ber_next_element, resulting in denial
 of service.

bsc#1182411 CVE-2020-36229 - ldap_X509dn2bv crash in the X.509 DN
 parsing in ad_keystring, resulting in denial of service.

bsc#1182412 CVE-2020-36228 - integer underflow leading to crash in the
 Certificate List Exact Assertion processing, resulting in denial of
 service.

bsc#1182413 CVE-2020-36227 - infinite loop in slapd with the
 cancel_extop Cancel operation, resulting in denial of service.

bsc#1182416 CVE-2020-36225 - double free and slapd crash in the
 saslAuthzTo processing, resulting in denial of service.

bsc#1182417 CVE-2020-36224 - invalid pointer free and slapd crash in the
 saslAuthzTo processing, resulting in denial of service.

bsc#1182415 CVE-2020-36226 - memch->bv_len miscalculation and slapd
 crash in the saslAuthzTo processing, resulting in denial of service.

bsc#1182419 CVE-2020-36222 - assertion failure in slapd in the
 saslAuthzTo validation, resulting in denial of service.

bsc#1182420 CVE-2020-36221 - slapd crashes in the Certificate Exact
 Assertion processing, resulting in denial of service (schema_init.c
 serialNumberAndIssuerCheck).

bsc#1182418 CVE-2020-36223 - slapd crash in the Values Return Filter
 control handling, resulting in denial of service (double free and
 out-of-bounds read).

bsc#1182279 CVE-2021-27212 - an assertion failure in slapd can occur in
 the issuerAndThisUpdateCheck function via a crafted packet, resulting in
 a denial of service (daemon exit) via a short timestamp. This is related
 to schema_init.c and checkTime.

resynchronise changelogs with subpackages (bsc#1184020).");

  script_tag(name:"affected", value:"'openldap2' package(s) on SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Server 11, SUSE Linux Enterprise Point of Sale 11-SP3, SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Debuginfo 11-SP3");

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
  if(!isnull(res = isrpmvuln(pkg:"compat-libldap-2_3-0", rpm:"compat-libldap-2_3-0~2.3.37~2.74.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2", rpm:"libldap-2_4-2~2.4.26~0.74.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2", rpm:"openldap2~2.4.26~0.74.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-back-meta", rpm:"openldap2-back-meta~2.4.26~0.74.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client", rpm:"openldap2-client~2.4.26~0.74.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-2_4-2-32bit", rpm:"libldap-2_4-2-32bit~2.4.26~0.74.26.1", rls:"SLES11.0SP4"))){
    report += res;
  }


  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES11.0") {
  if(!isnull(res = isrpmvuln(pkg:"libldap-openssl1-2_4-2", rpm:"libldap-openssl1-2_4-2~2.4.26~0.74.26.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-client-openssl1", rpm:"openldap2-client-openssl1~2.4.26~0.74.26.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"openldap2-openssl1", rpm:"openldap2-openssl1~2.4.26~0.74.26.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-openssl1-2_4-2-32bit", rpm:"libldap-openssl1-2_4-2-32bit~2.4.26~0.74.26.1", rls:"SLES11.0"))){
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libldap-openssl1-2_4-2-x86", rpm:"libldap-openssl1-2_4-2-x86~2.4.26~0.74.26.1", rls:"SLES11.0"))){
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
