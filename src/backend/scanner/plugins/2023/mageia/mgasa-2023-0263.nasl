# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0263");
  script_cve_id("CVE-2023-27533", "CVE-2023-27534", "CVE-2023-27535", "CVE-2023-27536", "CVE-2023-27537", "CVE-2023-27538", "CVE-2023-28319", "CVE-2023-28320", "CVE-2023-28321", "CVE-2023-28322", "CVE-2023-38039");
  script_tag(name:"creation_date", value:"2023-09-25 04:14:33 +0000 (Mon, 25 Sep 2023)");
  script_version("2023-09-25T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-25 05:05:21 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 16:23:00 +0000 (Fri, 07 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0263)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0263");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0263.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31703");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-27533.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-27534.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-27535.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-27536.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-27537.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-27538.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5964-1");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-28319.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-28320.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-28321.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-28322.html");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2023-May/014913.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-32001.html");
  script_xref(name:"URL", value:"https://curl.se/docs/CVE-2023-38039.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6363-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the MGASA-2023-0263 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"TELNET option IAC injection. (CVE-2023-27533)

SFTP path ~ resolving discrepancy. (CVE-2023-27534)

FTP too eager connection reuse. (CVE-2023-27535)

GSS delegation too eager connection re-use. (CVE-2023-27536)

HSTS double free. (CVE-2023-27537)

SSH connection too eager reuse still. (CVE-2023-27538)

UAF in SSH sha256 fingerprint check. (CVE-2023-28319)

siglongjmp race condition. (CVE-2023-28320)

IDN wildcard match. (CVE-2023-28321)

more POST-after-PUT confusion. (CVE-2023-28322)

HTTP headers eat all memory. (CVE-2023-38039)");

  script_tag(name:"affected", value:"'curl' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.74.0~1.13.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.74.0~1.13.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.74.0~1.13.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.74.0~1.13.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.74.0~1.13.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.74.0~1.13.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"curl", rpm:"curl~7.88.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"curl-examples", rpm:"curl-examples~7.88.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl-devel", rpm:"lib64curl-devel~7.88.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64curl4", rpm:"lib64curl4~7.88.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl-devel", rpm:"libcurl-devel~7.88.1~3.1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcurl4", rpm:"libcurl4~7.88.1~3.1.mga9", rls:"MAGEIA9"))) {
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
