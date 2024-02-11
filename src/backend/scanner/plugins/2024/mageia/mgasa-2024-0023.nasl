# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2024.0023");
  script_cve_id("CVE-2024-0741", "CVE-2024-0742", "CVE-2024-0746", "CVE-2024-0747", "CVE-2024-0749", "CVE-2024-0750", "CVE-2024-0751", "CVE-2024-0753", "CVE-2024-0755");
  script_tag(name:"creation_date", value:"2024-02-05 04:11:46 +0000 (Mon, 05 Feb 2024)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-29 22:47:49 +0000 (Mon, 29 Jan 2024)");

  script_name("Mageia: Security Advisory (MGASA-2024-0023)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2024-0023");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2024-0023.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32762");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/115.7.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2024-02/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox, firefox-l10n, nss' package(s) announced via the MGASA-2024-0023 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Out of bounds write in ANGLE. (CVE-2024-0741)

Failure to update user input timestamp. (CVE-2024-0742)

Crash when listing printers on Linux. (CVE-2024-0746)

Bypass of Content Security Policy when directive unsafe-inline was set.
(CVE-2024-0747)

Phishing site popup could show local origin in address bar.
(CVE-2024-0749)

Potential permissions request bypass via clickjacking. (CVE-2024-0750)

Privilege escalation through devtools. (CVE-2024-0751)

HSTS policy on subdomain could bypass policy of upper domain.
(CVE-2024-0753)

Memory safety bugs fixed in Firefox 122, Firefox ESR 115.7, and
Thunderbird 115.7. (CVE-2024-0755)");

  script_tag(name:"affected", value:"'firefox, firefox-l10n, nss' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-af", rpm:"firefox-af~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-an", rpm:"firefox-an~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ar", rpm:"firefox-ar~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ast", rpm:"firefox-ast~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-az", rpm:"firefox-az~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-be", rpm:"firefox-be~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bg", rpm:"firefox-bg~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bn", rpm:"firefox-bn~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-br", rpm:"firefox-br~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-bs", rpm:"firefox-bs~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ca", rpm:"firefox-ca~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cs", rpm:"firefox-cs~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-cy", rpm:"firefox-cy~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-da", rpm:"firefox-da~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-de", rpm:"firefox-de~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-el", rpm:"firefox-el~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_CA", rpm:"firefox-en_CA~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_GB", rpm:"firefox-en_GB~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-en_US", rpm:"firefox-en_US~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eo", rpm:"firefox-eo~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_AR", rpm:"firefox-es_AR~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_CL", rpm:"firefox-es_CL~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_ES", rpm:"firefox-es_ES~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-es_MX", rpm:"firefox-es_MX~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-et", rpm:"firefox-et~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-eu", rpm:"firefox-eu~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fa", rpm:"firefox-fa~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ff", rpm:"firefox-ff~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fi", rpm:"firefox-fi~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fr", rpm:"firefox-fr~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fur", rpm:"firefox-fur~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-fy_NL", rpm:"firefox-fy_NL~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ga_IE", rpm:"firefox-ga_IE~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gd", rpm:"firefox-gd~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gl", rpm:"firefox-gl~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-gu_IN", rpm:"firefox-gu_IN~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-he", rpm:"firefox-he~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hi_IN", rpm:"firefox-hi_IN~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hr", rpm:"firefox-hr~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hsb", rpm:"firefox-hsb~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hu", rpm:"firefox-hu~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-hy_AM", rpm:"firefox-hy_AM~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ia", rpm:"firefox-ia~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-id", rpm:"firefox-id~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-is", rpm:"firefox-is~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-it", rpm:"firefox-it~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ja", rpm:"firefox-ja~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ka", rpm:"firefox-ka~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kab", rpm:"firefox-kab~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kk", rpm:"firefox-kk~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-km", rpm:"firefox-km~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-kn", rpm:"firefox-kn~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ko", rpm:"firefox-ko~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-l10n", rpm:"firefox-l10n~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lij", rpm:"firefox-lij~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lt", rpm:"firefox-lt~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-lv", rpm:"firefox-lv~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mk", rpm:"firefox-mk~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-mr", rpm:"firefox-mr~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ms", rpm:"firefox-ms~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-my", rpm:"firefox-my~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nb_NO", rpm:"firefox-nb_NO~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nl", rpm:"firefox-nl~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-nn_NO", rpm:"firefox-nn_NO~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-oc", rpm:"firefox-oc~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pa_IN", rpm:"firefox-pa_IN~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pl", rpm:"firefox-pl~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_BR", rpm:"firefox-pt_BR~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-pt_PT", rpm:"firefox-pt_PT~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ro", rpm:"firefox-ro~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ru", rpm:"firefox-ru~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sc", rpm:"firefox-sc~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-si", rpm:"firefox-si~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sk", rpm:"firefox-sk~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sl", rpm:"firefox-sl~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sq", rpm:"firefox-sq~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sr", rpm:"firefox-sr~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-sv_SE", rpm:"firefox-sv_SE~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-szl", rpm:"firefox-szl~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ta", rpm:"firefox-ta~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-te", rpm:"firefox-te~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tg", rpm:"firefox-tg~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-th", rpm:"firefox-th~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tl", rpm:"firefox-tl~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-tr", rpm:"firefox-tr~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uk", rpm:"firefox-uk~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-ur", rpm:"firefox-ur~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-uz", rpm:"firefox-uz~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-vi", rpm:"firefox-vi~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-xh", rpm:"firefox-xh~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_CN", rpm:"firefox-zh_CN~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"firefox-zh_TW", rpm:"firefox-zh_TW~115.7.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss-devel", rpm:"lib64nss-devel~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss-static-devel", rpm:"lib64nss-static-devel~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64nss3", rpm:"lib64nss3~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss-devel", rpm:"libnss-devel~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss-static-devel", rpm:"libnss-static-devel~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libnss3", rpm:"libnss3~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss", rpm:"nss~3.97.0~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nss-doc", rpm:"nss-doc~3.97.0~1.mga9", rls:"MAGEIA9"))) {
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
