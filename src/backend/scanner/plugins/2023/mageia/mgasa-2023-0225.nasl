# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0225");
  script_cve_id("CVE-2023-1183");
  script_tag(name:"creation_date", value:"2023-07-10 04:12:52 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-19T05:05:15+0000");
  script_tag(name:"last_modification", value:"2023-07-19 05:05:15 +0000 (Wed, 19 Jul 2023)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-17 18:13:00 +0000 (Mon, 17 Jul 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0225)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0225");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0225.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32042");
  script_xref(name:"URL", value:"https://www.libreoffice.org/about-us/security/advisories/cve-2023-1183/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libreoffice' package(s) announced via the MGASA-2023-0225 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Arbitrary File Write in hsqldb 1.8.0. (CVE-2023-1183)");

  script_tag(name:"affected", value:"'libreoffice' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"autocorr-af", rpm:"autocorr-af~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-bg", rpm:"autocorr-bg~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ca", rpm:"autocorr-ca~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-cs", rpm:"autocorr-cs~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-da", rpm:"autocorr-da~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-de", rpm:"autocorr-de~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-dsb", rpm:"autocorr-dsb~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-el", rpm:"autocorr-el~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-en", rpm:"autocorr-en~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-es", rpm:"autocorr-es~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fa", rpm:"autocorr-fa~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fi", rpm:"autocorr-fi~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-fr", rpm:"autocorr-fr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ga", rpm:"autocorr-ga~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-hr", rpm:"autocorr-hr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-hsb", rpm:"autocorr-hsb~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-hu", rpm:"autocorr-hu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-is", rpm:"autocorr-is~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-it", rpm:"autocorr-it~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ja", rpm:"autocorr-ja~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ko", rpm:"autocorr-ko~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-lb", rpm:"autocorr-lb~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-lt", rpm:"autocorr-lt~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-mn", rpm:"autocorr-mn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-nl", rpm:"autocorr-nl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-pl", rpm:"autocorr-pl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-pt", rpm:"autocorr-pt~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ro", rpm:"autocorr-ro~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-ru", rpm:"autocorr-ru~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sk", rpm:"autocorr-sk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sl", rpm:"autocorr-sl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sr", rpm:"autocorr-sr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-sv", rpm:"autocorr-sv~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-tr", rpm:"autocorr-tr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-vi", rpm:"autocorr-vi~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-vro", rpm:"autocorr-vro~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"autocorr-zh", rpm:"autocorr-zh~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice", rpm:"libreoffice~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-base", rpm:"libreoffice-base~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-calc", rpm:"libreoffice-calc~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-core", rpm:"libreoffice-core~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-data", rpm:"libreoffice-data~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-draw", rpm:"libreoffice-draw~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-emailmerge", rpm:"libreoffice-emailmerge~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-filters", rpm:"libreoffice-filters~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gdb-debug-support", rpm:"libreoffice-gdb-debug-support~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-glade", rpm:"libreoffice-glade~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-graphicfilter", rpm:"libreoffice-graphicfilter~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-gtk3", rpm:"libreoffice-gtk3~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ar", rpm:"libreoffice-help-ar~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-bg", rpm:"libreoffice-help-bg~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-bn", rpm:"libreoffice-help-bn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ca", rpm:"libreoffice-help-ca~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-cs", rpm:"libreoffice-help-cs~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-da", rpm:"libreoffice-help-da~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-de", rpm:"libreoffice-help-de~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-dz", rpm:"libreoffice-help-dz~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-el", rpm:"libreoffice-help-el~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-en", rpm:"libreoffice-help-en~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-eo", rpm:"libreoffice-help-eo~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-es", rpm:"libreoffice-help-es~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-et", rpm:"libreoffice-help-et~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-eu", rpm:"libreoffice-help-eu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-fi", rpm:"libreoffice-help-fi~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-fr", rpm:"libreoffice-help-fr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-gl", rpm:"libreoffice-help-gl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-gu", rpm:"libreoffice-help-gu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-he", rpm:"libreoffice-help-he~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-hi", rpm:"libreoffice-help-hi~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-hr", rpm:"libreoffice-help-hr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-hu", rpm:"libreoffice-help-hu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-id", rpm:"libreoffice-help-id~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-it", rpm:"libreoffice-help-it~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ja", rpm:"libreoffice-help-ja~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ko", rpm:"libreoffice-help-ko~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-lt", rpm:"libreoffice-help-lt~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-lv", rpm:"libreoffice-help-lv~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-nb", rpm:"libreoffice-help-nb~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-nl", rpm:"libreoffice-help-nl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-nn", rpm:"libreoffice-help-nn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-pl", rpm:"libreoffice-help-pl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-pt", rpm:"libreoffice-help-pt~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-pt_BR", rpm:"libreoffice-help-pt_BR~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ro", rpm:"libreoffice-help-ro~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ru", rpm:"libreoffice-help-ru~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-si", rpm:"libreoffice-help-si~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-sk", rpm:"libreoffice-help-sk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-sl", rpm:"libreoffice-help-sl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-sv", rpm:"libreoffice-help-sv~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-ta", rpm:"libreoffice-help-ta~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-tr", rpm:"libreoffice-help-tr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-uk", rpm:"libreoffice-help-uk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-zh_CN", rpm:"libreoffice-help-zh_CN~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-help-zh_TW", rpm:"libreoffice-help-zh_TW~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-impress", rpm:"libreoffice-impress~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-kf5", rpm:"libreoffice-kf5~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-af", rpm:"libreoffice-langpack-af~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ar", rpm:"libreoffice-langpack-ar~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-as", rpm:"libreoffice-langpack-as~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-bg", rpm:"libreoffice-langpack-bg~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-bn", rpm:"libreoffice-langpack-bn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-br", rpm:"libreoffice-langpack-br~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ca", rpm:"libreoffice-langpack-ca~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-cs", rpm:"libreoffice-langpack-cs~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-cy", rpm:"libreoffice-langpack-cy~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-da", rpm:"libreoffice-langpack-da~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-de", rpm:"libreoffice-langpack-de~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-dz", rpm:"libreoffice-langpack-dz~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-el", rpm:"libreoffice-langpack-el~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-en", rpm:"libreoffice-langpack-en~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-eo", rpm:"libreoffice-langpack-eo~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-es", rpm:"libreoffice-langpack-es~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-et", rpm:"libreoffice-langpack-et~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-eu", rpm:"libreoffice-langpack-eu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fa", rpm:"libreoffice-langpack-fa~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fi", rpm:"libreoffice-langpack-fi~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fr", rpm:"libreoffice-langpack-fr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-fy", rpm:"libreoffice-langpack-fy~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ga", rpm:"libreoffice-langpack-ga~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-gl", rpm:"libreoffice-langpack-gl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-gu", rpm:"libreoffice-langpack-gu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-he", rpm:"libreoffice-langpack-he~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-hi", rpm:"libreoffice-langpack-hi~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-hr", rpm:"libreoffice-langpack-hr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-hu", rpm:"libreoffice-langpack-hu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-id", rpm:"libreoffice-langpack-id~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-it", rpm:"libreoffice-langpack-it~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ja", rpm:"libreoffice-langpack-ja~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-kk", rpm:"libreoffice-langpack-kk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-kn", rpm:"libreoffice-langpack-kn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ko", rpm:"libreoffice-langpack-ko~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-lt", rpm:"libreoffice-langpack-lt~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-lv", rpm:"libreoffice-langpack-lv~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-mai", rpm:"libreoffice-langpack-mai~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ml", rpm:"libreoffice-langpack-ml~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-mr", rpm:"libreoffice-langpack-mr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nb", rpm:"libreoffice-langpack-nb~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nl", rpm:"libreoffice-langpack-nl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nn", rpm:"libreoffice-langpack-nn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nr", rpm:"libreoffice-langpack-nr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-nso", rpm:"libreoffice-langpack-nso~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-or", rpm:"libreoffice-langpack-or~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pa", rpm:"libreoffice-langpack-pa~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pl", rpm:"libreoffice-langpack-pl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pt", rpm:"libreoffice-langpack-pt~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-pt_BR", rpm:"libreoffice-langpack-pt_BR~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ro", rpm:"libreoffice-langpack-ro~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ru", rpm:"libreoffice-langpack-ru~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-si", rpm:"libreoffice-langpack-si~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sk", rpm:"libreoffice-langpack-sk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sl", rpm:"libreoffice-langpack-sl~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sr", rpm:"libreoffice-langpack-sr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ss", rpm:"libreoffice-langpack-ss~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-st", rpm:"libreoffice-langpack-st~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-sv", rpm:"libreoffice-langpack-sv~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ta", rpm:"libreoffice-langpack-ta~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-te", rpm:"libreoffice-langpack-te~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-th", rpm:"libreoffice-langpack-th~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-tn", rpm:"libreoffice-langpack-tn~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-tr", rpm:"libreoffice-langpack-tr~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ts", rpm:"libreoffice-langpack-ts~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-uk", rpm:"libreoffice-langpack-uk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-ve", rpm:"libreoffice-langpack-ve~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-xh", rpm:"libreoffice-langpack-xh~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-zh_CN", rpm:"libreoffice-langpack-zh_CN~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-zh_TW", rpm:"libreoffice-langpack-zh_TW~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-langpack-zu", rpm:"libreoffice-langpack-zu~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-librelogo", rpm:"libreoffice-librelogo~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-math", rpm:"libreoffice-math~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-nlpsolver", rpm:"libreoffice-nlpsolver~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean", rpm:"libreoffice-officebean~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-officebean-common", rpm:"libreoffice-officebean-common~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ogltrans", rpm:"libreoffice-ogltrans~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-opensymbol-fonts", rpm:"libreoffice-opensymbol-fonts~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pdfimport", rpm:"libreoffice-pdfimport~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-postgresql", rpm:"libreoffice-postgresql~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-pyuno", rpm:"libreoffice-pyuno~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk", rpm:"libreoffice-sdk~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-sdk-doc", rpm:"libreoffice-sdk-doc~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ure", rpm:"libreoffice-ure~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-ure-common", rpm:"libreoffice-ure-common~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-wiki-publisher", rpm:"libreoffice-wiki-publisher~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-writer", rpm:"libreoffice-writer~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-x11", rpm:"libreoffice-x11~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreoffice-xsltfilter", rpm:"libreoffice-xsltfilter~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit", rpm:"libreofficekit~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libreofficekit-devel", rpm:"libreofficekit-devel~7.4.5.1~1.2.mga8", rls:"MAGEIA8"))) {
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
