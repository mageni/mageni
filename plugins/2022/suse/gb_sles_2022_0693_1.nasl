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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.0693.1");
  script_cve_id("CVE-2022-24407");
  script_tag(name:"creation_date", value:"2022-03-04 04:07:05 +0000 (Fri, 04 Mar 2022)");
  script_version("2022-03-04T04:07:05+0000");
  script_tag(name:"last_modification", value:"2022-03-04 10:35:15 +0000 (Fri, 04 Mar 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-03-04 04:07:05 +0000 (Fri, 04 Mar 2022)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:0693-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP4|SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:0693-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20220693-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl' package(s) announced via the SUSE-SU-2022:0693-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cyrus-sasl fixes the following issues:

 CVE-2022-24407: Fixed SQL injection in sql_auxprop_store in
 plugins/sql.c (bsc#1196036).");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 9.");

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

if(release == "SLES12.0SP4") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo-32bit", rpm:"cyrus-sasl-crammd5-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo-32bit", rpm:"cyrus-sasl-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo-32bit", rpm:"cyrus-sasl-gssapi-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit", rpm:"cyrus-sasl-otp-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo-32bit", rpm:"cyrus-sasl-otp-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo-32bit", rpm:"cyrus-sasl-plain-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit", rpm:"cyrus-sasl-sqlauxprop-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo-32bit", rpm:"cyrus-sasl-sqlauxprop-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit", rpm:"libsasl2-3-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo-32bit", rpm:"libsasl2-3-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo-32bit", rpm:"cyrus-sasl-crammd5-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo-32bit", rpm:"cyrus-sasl-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo-32bit", rpm:"cyrus-sasl-gssapi-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-32bit", rpm:"cyrus-sasl-otp-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo-32bit", rpm:"cyrus-sasl-otp-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo-32bit", rpm:"cyrus-sasl-plain-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-32bit", rpm:"cyrus-sasl-sqlauxprop-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo-32bit", rpm:"cyrus-sasl-sqlauxprop-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit", rpm:"libsasl2-3-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo-32bit", rpm:"libsasl2-3-debuginfo-32bit~2.1.26~14.5.1", rls:"SLES12.0SP5"))) {
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
