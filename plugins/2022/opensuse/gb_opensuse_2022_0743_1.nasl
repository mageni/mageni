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
  script_oid("1.3.6.1.4.1.25623.1.0.854547");
  script_version("2022-03-24T14:03:56+0000");
  script_cve_id("CVE-2022-24407");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 19:08:00 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 08:27:52 +0000 (Wed, 23 Mar 2022)");
  script_name("openSUSE: Security Advisory for cyrus-sasl (openSUSE-SU-2022:0743-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2022:0743-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/BPABQLPWLWVSDVE54YNNZUHMKWEV6F3X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl'
  package(s) announced via the openSUSE-SU-2022:0743-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cyrus-sasl fixes the following issues:
  - CVE-2022-24407: Fixed SQL injection in sql_auxprop_store in
       plugins/sql.c (bsc#1196036).
  The following non-security bugs were fixed:
  - postfix: sasl authentication with password fails (bsc#1194265).");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb", rpm:"cyrus-sasl-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-crammd5", rpm:"cyrus-sasl-bdb-crammd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-crammd5-debuginfo", rpm:"cyrus-sasl-bdb-crammd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-debuginfo", rpm:"cyrus-sasl-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-debugsource", rpm:"cyrus-sasl-bdb-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-devel", rpm:"cyrus-sasl-bdb-devel~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-digestmd5", rpm:"cyrus-sasl-bdb-digestmd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-digestmd5-debuginfo", rpm:"cyrus-sasl-bdb-digestmd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gs2", rpm:"cyrus-sasl-bdb-gs2~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gs2-debuginfo", rpm:"cyrus-sasl-bdb-gs2-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gssapi", rpm:"cyrus-sasl-bdb-gssapi~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gssapi-debuginfo", rpm:"cyrus-sasl-bdb-gssapi-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-ntlm", rpm:"cyrus-sasl-bdb-ntlm~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-ntlm-debuginfo", rpm:"cyrus-sasl-bdb-ntlm-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-otp", rpm:"cyrus-sasl-bdb-otp~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-otp-debuginfo", rpm:"cyrus-sasl-bdb-otp-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-plain", rpm:"cyrus-sasl-bdb-plain~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-plain-debuginfo", rpm:"cyrus-sasl-bdb-plain-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-scram", rpm:"cyrus-sasl-bdb-scram~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-scram-debuginfo", rpm:"cyrus-sasl-bdb-scram-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gs2", rpm:"cyrus-sasl-gs2~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gs2-debuginfo", rpm:"cyrus-sasl-gs2-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop", rpm:"cyrus-sasl-ldap-auxprop~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-bdb", rpm:"cyrus-sasl-ldap-auxprop-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-bdb-debuginfo", rpm:"cyrus-sasl-ldap-auxprop-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-debuginfo", rpm:"cyrus-sasl-ldap-auxprop-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ntlm", rpm:"cyrus-sasl-ntlm~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ntlm-debuginfo", rpm:"cyrus-sasl-ntlm-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-bdb", rpm:"cyrus-sasl-saslauthd-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-bdb-debuginfo", rpm:"cyrus-sasl-saslauthd-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-bdb-debugsource", rpm:"cyrus-sasl-saslauthd-bdb-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-scram", rpm:"cyrus-sasl-scram~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-scram-debuginfo", rpm:"cyrus-sasl-scram-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-bdb", rpm:"cyrus-sasl-sqlauxprop-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-bdb-debuginfo", rpm:"cyrus-sasl-sqlauxprop-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit-debuginfo", rpm:"cyrus-sasl-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit-debuginfo", rpm:"cyrus-sasl-crammd5-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel-32bit", rpm:"cyrus-sasl-devel-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit", rpm:"cyrus-sasl-digestmd5-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit-debuginfo", rpm:"cyrus-sasl-digestmd5-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit-debuginfo", rpm:"cyrus-sasl-gssapi-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-32bit", rpm:"cyrus-sasl-ldap-auxprop-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-32bit-debuginfo", rpm:"cyrus-sasl-ldap-auxprop-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit", rpm:"cyrus-sasl-otp-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit-debuginfo", rpm:"cyrus-sasl-otp-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit-debuginfo", rpm:"cyrus-sasl-plain-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit", rpm:"cyrus-sasl-sqlauxprop-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit-debuginfo", rpm:"cyrus-sasl-sqlauxprop-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit", rpm:"libsasl2-3-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit-debuginfo", rpm:"libsasl2-3-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb", rpm:"cyrus-sasl-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-crammd5", rpm:"cyrus-sasl-bdb-crammd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-crammd5-debuginfo", rpm:"cyrus-sasl-bdb-crammd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-debuginfo", rpm:"cyrus-sasl-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-debugsource", rpm:"cyrus-sasl-bdb-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-devel", rpm:"cyrus-sasl-bdb-devel~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-digestmd5", rpm:"cyrus-sasl-bdb-digestmd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-digestmd5-debuginfo", rpm:"cyrus-sasl-bdb-digestmd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gs2", rpm:"cyrus-sasl-bdb-gs2~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gs2-debuginfo", rpm:"cyrus-sasl-bdb-gs2-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gssapi", rpm:"cyrus-sasl-bdb-gssapi~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-gssapi-debuginfo", rpm:"cyrus-sasl-bdb-gssapi-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-ntlm", rpm:"cyrus-sasl-bdb-ntlm~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-ntlm-debuginfo", rpm:"cyrus-sasl-bdb-ntlm-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-otp", rpm:"cyrus-sasl-bdb-otp~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-otp-debuginfo", rpm:"cyrus-sasl-bdb-otp-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-plain", rpm:"cyrus-sasl-bdb-plain~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-plain-debuginfo", rpm:"cyrus-sasl-bdb-plain-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-scram", rpm:"cyrus-sasl-bdb-scram~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-bdb-scram-debuginfo", rpm:"cyrus-sasl-bdb-scram-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gs2", rpm:"cyrus-sasl-gs2~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gs2-debuginfo", rpm:"cyrus-sasl-gs2-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop", rpm:"cyrus-sasl-ldap-auxprop~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-bdb", rpm:"cyrus-sasl-ldap-auxprop-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-bdb-debuginfo", rpm:"cyrus-sasl-ldap-auxprop-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-debuginfo", rpm:"cyrus-sasl-ldap-auxprop-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ntlm", rpm:"cyrus-sasl-ntlm~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ntlm-debuginfo", rpm:"cyrus-sasl-ntlm-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-bdb", rpm:"cyrus-sasl-saslauthd-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-bdb-debuginfo", rpm:"cyrus-sasl-saslauthd-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-bdb-debugsource", rpm:"cyrus-sasl-saslauthd-bdb-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-scram", rpm:"cyrus-sasl-scram~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-scram-debuginfo", rpm:"cyrus-sasl-scram-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-bdb", rpm:"cyrus-sasl-sqlauxprop-bdb~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-bdb-debuginfo", rpm:"cyrus-sasl-sqlauxprop-bdb-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit-debuginfo", rpm:"cyrus-sasl-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit-debuginfo", rpm:"cyrus-sasl-crammd5-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel-32bit", rpm:"cyrus-sasl-devel-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit", rpm:"cyrus-sasl-digestmd5-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit-debuginfo", rpm:"cyrus-sasl-digestmd5-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit-debuginfo", rpm:"cyrus-sasl-gssapi-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-32bit", rpm:"cyrus-sasl-ldap-auxprop-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-ldap-auxprop-32bit-debuginfo", rpm:"cyrus-sasl-ldap-auxprop-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit", rpm:"cyrus-sasl-otp-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit-debuginfo", rpm:"cyrus-sasl-otp-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit-debuginfo", rpm:"cyrus-sasl-plain-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit", rpm:"cyrus-sasl-sqlauxprop-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit-debuginfo", rpm:"cyrus-sasl-sqlauxprop-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit", rpm:"libsasl2-3-32bit~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit-debuginfo", rpm:"libsasl2-3-32bit-debuginfo~2.1.27~150300.4.6.1", rls:"openSUSELeap15.3"))) {
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