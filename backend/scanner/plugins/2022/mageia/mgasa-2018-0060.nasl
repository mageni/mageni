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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0060");
  script_cve_id("CVE-2017-1000385");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Mageia: Security Advisory (MGASA-2018-0060)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0060");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0060.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22145");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-4057");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang' package(s) announced via the MGASA-2018-0060 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the TLS server in Erlang is vulnerable to an
adaptive chosen ciphertext attack against RSA keys (CVE-2017-1000385).");

  script_tag(name:"affected", value:"'erlang' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"emacs-erlang", rpm:"emacs-erlang~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang", rpm:"erlang~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-asn1", rpm:"erlang-asn1~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-common_test", rpm:"erlang-common_test~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-compiler", rpm:"erlang-compiler~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosEvent", rpm:"erlang-cosEvent~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosEventDomain", rpm:"erlang-cosEventDomain~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosFileTransfer", rpm:"erlang-cosFileTransfer~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosNotification", rpm:"erlang-cosNotification~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosProperty", rpm:"erlang-cosProperty~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosTime", rpm:"erlang-cosTime~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-cosTransactions", rpm:"erlang-cosTransactions~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-crypto", rpm:"erlang-crypto~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-debugger", rpm:"erlang-debugger~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-dialyzer", rpm:"erlang-dialyzer~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-diameter", rpm:"erlang-diameter~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-doc", rpm:"erlang-doc~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-edoc", rpm:"erlang-edoc~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-eldap", rpm:"erlang-eldap~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erl_docgen", rpm:"erlang-erl_docgen~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erl_interface", rpm:"erlang-erl_interface~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erts", rpm:"erlang-erts~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-et", rpm:"erlang-et~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-eunit", rpm:"erlang-eunit~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-examples", rpm:"erlang-examples~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-gs", rpm:"erlang-gs~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-hipe", rpm:"erlang-hipe~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ic", rpm:"erlang-ic~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-inets", rpm:"erlang-inets~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-jinterface", rpm:"erlang-jinterface~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-kernel", rpm:"erlang-kernel~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-megaco", rpm:"erlang-megaco~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-mnesia", rpm:"erlang-mnesia~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-observer", rpm:"erlang-observer~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-odbc", rpm:"erlang-odbc~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-orber", rpm:"erlang-orber~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-os_mon", rpm:"erlang-os_mon~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ose", rpm:"erlang-ose~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-otp_mibs", rpm:"erlang-otp_mibs~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-parsetools", rpm:"erlang-parsetools~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-percept", rpm:"erlang-percept~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-public_key", rpm:"erlang-public_key~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-reltool", rpm:"erlang-reltool~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-runtime_tools", rpm:"erlang-runtime_tools~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-sasl", rpm:"erlang-sasl~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-snmp", rpm:"erlang-snmp~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ssh", rpm:"erlang-ssh~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ssl", rpm:"erlang-ssl~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-stdlib", rpm:"erlang-stdlib~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-syntax_tools", rpm:"erlang-syntax_tools~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-test_server", rpm:"erlang-test_server~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-tools", rpm:"erlang-tools~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-typer", rpm:"erlang-typer~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-webtool", rpm:"erlang-webtool~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-wx", rpm:"erlang-wx~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-xmerl", rpm:"erlang-xmerl~18.3.2~9.1.mga6", rls:"MAGEIA6"))) {
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
