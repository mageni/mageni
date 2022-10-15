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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2022.3549.1");
  script_cve_id("CVE-2019-19906");
  script_tag(name:"creation_date", value:"2022-10-10 04:49:30 +0000 (Mon, 10 Oct 2022)");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 15:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2022:3549-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0|SLES15\.0SP1|SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:3549-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2022/suse-su-20223549-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cyrus-sasl' package(s) announced via the SUSE-SU-2022:3549-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for cyrus-sasl fixes the following issues:

CVE-2019-19906: Fixed an out-of-bounds write that could lead to
 unauthenticated remote denial of service in OpenLDAP via a malformed
 LDAP packet (bsc#1159635).");

  script_tag(name:"affected", value:"'cyrus-sasl' package(s) on SUSE CaaS Platform 4.0, SUSE Enterprise Storage 6, SUSE Enterprise Storage 7, SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise High Performance Computing 15-SP1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server 15-SP1, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP 15, SUSE Linux Enterprise Server for SAP 15-SP1, SUSE Linux Enterprise Server for SAP 15-SP2, SUSE Manager Proxy 4.1, SUSE Manager Retail Branch Server 4.1, SUSE Manager Server 4.1.");

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

if(release == "SLES15.0") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP1") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit-debuginfo", rpm:"cyrus-sasl-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit-debuginfo", rpm:"cyrus-sasl-crammd5-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit", rpm:"cyrus-sasl-digestmd5-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit-debuginfo", rpm:"cyrus-sasl-digestmd5-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit-debuginfo", rpm:"cyrus-sasl-gssapi-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit-debuginfo", rpm:"cyrus-sasl-plain-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit", rpm:"libsasl2-3-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit-debuginfo", rpm:"libsasl2-3-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP1"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl", rpm:"cyrus-sasl~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit", rpm:"cyrus-sasl-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-32bit-debuginfo", rpm:"cyrus-sasl-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5", rpm:"cyrus-sasl-crammd5~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit", rpm:"cyrus-sasl-crammd5-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-32bit-debuginfo", rpm:"cyrus-sasl-crammd5-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-crammd5-debuginfo", rpm:"cyrus-sasl-crammd5-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debuginfo", rpm:"cyrus-sasl-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-debugsource", rpm:"cyrus-sasl-debugsource~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-devel", rpm:"cyrus-sasl-devel~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5", rpm:"cyrus-sasl-digestmd5~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit", rpm:"cyrus-sasl-digestmd5-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-32bit-debuginfo", rpm:"cyrus-sasl-digestmd5-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-digestmd5-debuginfo", rpm:"cyrus-sasl-digestmd5-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi", rpm:"cyrus-sasl-gssapi~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit", rpm:"cyrus-sasl-gssapi-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-32bit-debuginfo", rpm:"cyrus-sasl-gssapi-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-gssapi-debuginfo", rpm:"cyrus-sasl-gssapi-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp", rpm:"cyrus-sasl-otp~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-otp-debuginfo", rpm:"cyrus-sasl-otp-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain", rpm:"cyrus-sasl-plain~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit", rpm:"cyrus-sasl-plain-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-32bit-debuginfo", rpm:"cyrus-sasl-plain-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-plain-debuginfo", rpm:"cyrus-sasl-plain-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd", rpm:"cyrus-sasl-saslauthd~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debuginfo", rpm:"cyrus-sasl-saslauthd-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-saslauthd-debugsource", rpm:"cyrus-sasl-saslauthd-debugsource~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop", rpm:"cyrus-sasl-sqlauxprop~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"cyrus-sasl-sqlauxprop-debuginfo", rpm:"cyrus-sasl-sqlauxprop-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3", rpm:"libsasl2-3~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit", rpm:"libsasl2-3-32bit~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-32bit-debuginfo", rpm:"libsasl2-3-32bit-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libsasl2-3-debuginfo", rpm:"libsasl2-3-debuginfo~2.1.26~150000.5.13.1", rls:"SLES15.0SP2"))) {
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
