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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0450");
  script_cve_id("CVE-2022-37026");
  script_tag(name:"creation_date", value:"2022-12-07 04:12:01 +0000 (Wed, 07 Dec 2022)");
  script_version("2022-12-07T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-12-07 10:11:17 +0000 (Wed, 07 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-09-23 18:05:00 +0000 (Fri, 23 Sep 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0450)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0450");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0450.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31190");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-November/013107.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FKGB2TBMVRY5L4FUEC3LM2R2WTCDC2Y7/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang' package(s) announced via the MGASA-2022-0450 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Erlang/OTP before 23.3.4.15, 24.x before 24.3.4.2, and 25.x before
25.0.2, there is a Client Authentication Bypass in certain
client-certification situations for SSL, TLS, and DTLS. (CVE-2022-37026)");

  script_tag(name:"affected", value:"'erlang' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"erlang", rpm:"erlang~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-asn1", rpm:"erlang-asn1~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-common_test", rpm:"erlang-common_test~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-compiler", rpm:"erlang-compiler~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-crypto", rpm:"erlang-crypto~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-debugger", rpm:"erlang-debugger~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-dialyzer", rpm:"erlang-dialyzer~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-diameter", rpm:"erlang-diameter~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-doc", rpm:"erlang-doc~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-edoc", rpm:"erlang-edoc~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-eldap", rpm:"erlang-eldap~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erl_docgen", rpm:"erlang-erl_docgen~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erl_interface", rpm:"erlang-erl_interface~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erts", rpm:"erlang-erts~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-et", rpm:"erlang-et~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-eunit", rpm:"erlang-eunit~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-examples", rpm:"erlang-examples~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ftp", rpm:"erlang-ftp~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-hipe", rpm:"erlang-hipe~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-inets", rpm:"erlang-inets~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-jinterface", rpm:"erlang-jinterface~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-kernel", rpm:"erlang-kernel~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-megaco", rpm:"erlang-megaco~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-mnesia", rpm:"erlang-mnesia~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-observer", rpm:"erlang-observer~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-odbc", rpm:"erlang-odbc~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-os_mon", rpm:"erlang-os_mon~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-parsetools", rpm:"erlang-parsetools~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-public_key", rpm:"erlang-public_key~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-reltool", rpm:"erlang-reltool~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-runtime_tools", rpm:"erlang-runtime_tools~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-sasl", rpm:"erlang-sasl~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-snmp", rpm:"erlang-snmp~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ssh", rpm:"erlang-ssh~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ssl", rpm:"erlang-ssl~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-stdlib", rpm:"erlang-stdlib~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-syntax_tools", rpm:"erlang-syntax_tools~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-tftp", rpm:"erlang-tftp~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-tools", rpm:"erlang-tools~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-wx", rpm:"erlang-wx~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-xmerl", rpm:"erlang-xmerl~23.2.1~3.2.mga8", rls:"MAGEIA8"))) {
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
