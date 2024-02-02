# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0015");
  script_cve_id("CVE-2023-48795");
  script_tag(name:"creation_date", value:"2024-01-22 04:12:22 +0000 (Mon, 22 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-28 18:26:44 +0000 (Thu, 28 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2024-0015)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0015");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0015.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32670");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/18/3");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/19/5");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/12/20/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'erlang' package(s) announced via the MGASA-2024-0015 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix a security vulnerability:
Prefix Truncation Attacks in SSH Specification (Terrapin Attack):
erlang-ssh. (CVE-2023-48795)");

  script_tag(name:"affected", value:"'erlang' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"erlang", rpm:"erlang~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-asn1", rpm:"erlang-asn1~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-common_test", rpm:"erlang-common_test~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-compiler", rpm:"erlang-compiler~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-crypto", rpm:"erlang-crypto~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-debugger", rpm:"erlang-debugger~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-dialyzer", rpm:"erlang-dialyzer~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-diameter", rpm:"erlang-diameter~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-doc", rpm:"erlang-doc~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-edoc", rpm:"erlang-edoc~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-eldap", rpm:"erlang-eldap~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erl_docgen", rpm:"erlang-erl_docgen~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erl_interface", rpm:"erlang-erl_interface~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-erts", rpm:"erlang-erts~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-et", rpm:"erlang-et~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-eunit", rpm:"erlang-eunit~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-examples", rpm:"erlang-examples~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ftp", rpm:"erlang-ftp~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-inets", rpm:"erlang-inets~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-jinterface", rpm:"erlang-jinterface~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-kernel", rpm:"erlang-kernel~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-megaco", rpm:"erlang-megaco~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-mnesia", rpm:"erlang-mnesia~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-observer", rpm:"erlang-observer~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-odbc", rpm:"erlang-odbc~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-os_mon", rpm:"erlang-os_mon~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-parsetools", rpm:"erlang-parsetools~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-public_key", rpm:"erlang-public_key~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-reltool", rpm:"erlang-reltool~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-runtime_tools", rpm:"erlang-runtime_tools~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-sasl", rpm:"erlang-sasl~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-snmp", rpm:"erlang-snmp~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ssh", rpm:"erlang-ssh~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-ssl", rpm:"erlang-ssl~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-stdlib", rpm:"erlang-stdlib~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-syntax_tools", rpm:"erlang-syntax_tools~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-tftp", rpm:"erlang-tftp~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-tools", rpm:"erlang-tools~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-wx", rpm:"erlang-wx~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"erlang-xmerl", rpm:"erlang-xmerl~24.3.4.15~1.mga9", rls:"MAGEIA9"))) {
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
