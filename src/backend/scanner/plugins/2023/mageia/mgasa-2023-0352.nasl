# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0352");
  script_cve_id("CVE-2022-36179", "CVE-2022-36180");
  script_tag(name:"creation_date", value:"2023-12-20 04:14:11 +0000 (Wed, 20 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-28 13:59:47 +0000 (Mon, 28 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0352)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(8|9)");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0352");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0352.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32092");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3487");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'fusiondirectory' package(s) announced via the MGASA-2023-0352 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities:
Fusiondirectory 1.3 suffers from Improper Session Handling.
(CVE-2022-36179)
Fusiondirectory 1.3 is vulnerable to Cross Site Scripting (XSS) via
/fusiondirectory/index.php?message=[injection],
/fusiondirectory/index.php?message=invalidparameter&plug={Injection],
/fusiondirectory/index.php?signout=1&message=[injection]&plug=106.
(CVE-2022-36180)");

  script_tag(name:"affected", value:"'fusiondirectory' package(s) on Mageia 8, Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory", rpm:"fusiondirectory~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-database", rpm:"fusiondirectory-database~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-alias", rpm:"fusiondirectory-plugin-alias~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-applications", rpm:"fusiondirectory-plugin-applications~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-argonaut", rpm:"fusiondirectory-plugin-argonaut~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-audit", rpm:"fusiondirectory-plugin-audit~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-autofs", rpm:"fusiondirectory-plugin-autofs~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-certificates", rpm:"fusiondirectory-plugin-certificates~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-community", rpm:"fusiondirectory-plugin-community~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-cyrus", rpm:"fusiondirectory-plugin-cyrus~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-debconf", rpm:"fusiondirectory-plugin-debconf~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-developers", rpm:"fusiondirectory-plugin-developers~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dhcp", rpm:"fusiondirectory-plugin-dhcp~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dns", rpm:"fusiondirectory-plugin-dns~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dovecot", rpm:"fusiondirectory-plugin-dovecot~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dsa", rpm:"fusiondirectory-plugin-dsa~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ejbca", rpm:"fusiondirectory-plugin-ejbca~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-fai", rpm:"fusiondirectory-plugin-fai~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-freeradius", rpm:"fusiondirectory-plugin-freeradius~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-fusioninventory", rpm:"fusiondirectory-plugin-fusioninventory~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-gpg", rpm:"fusiondirectory-plugin-gpg~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ipmi", rpm:"fusiondirectory-plugin-ipmi~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-kolab2", rpm:"fusiondirectory-plugin-kolab2~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ldapdump", rpm:"fusiondirectory-plugin-ldapdump~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ldapmanager", rpm:"fusiondirectory-plugin-ldapmanager~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-mail", rpm:"fusiondirectory-plugin-mail~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-mixedgroups", rpm:"fusiondirectory-plugin-mixedgroups~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-nagios", rpm:"fusiondirectory-plugin-nagios~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-netgroups", rpm:"fusiondirectory-plugin-netgroups~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-newsletter", rpm:"fusiondirectory-plugin-newsletter~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-opsi", rpm:"fusiondirectory-plugin-opsi~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-personal", rpm:"fusiondirectory-plugin-personal~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-posix", rpm:"fusiondirectory-plugin-posix~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ppolicy", rpm:"fusiondirectory-plugin-ppolicy~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-puppet", rpm:"fusiondirectory-plugin-puppet~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-pureftpd", rpm:"fusiondirectory-plugin-pureftpd~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-quota", rpm:"fusiondirectory-plugin-quota~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-renater-partage", rpm:"fusiondirectory-plugin-renater-partage~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-repository", rpm:"fusiondirectory-plugin-repository~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-samba", rpm:"fusiondirectory-plugin-samba~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sinaps", rpm:"fusiondirectory-plugin-sinaps~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sogo", rpm:"fusiondirectory-plugin-sogo~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-spamassassin", rpm:"fusiondirectory-plugin-spamassassin~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-squid", rpm:"fusiondirectory-plugin-squid~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ssh", rpm:"fusiondirectory-plugin-ssh~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-subcontracting", rpm:"fusiondirectory-plugin-subcontracting~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sudo", rpm:"fusiondirectory-plugin-sudo~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-supann", rpm:"fusiondirectory-plugin-supann~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sympa", rpm:"fusiondirectory-plugin-sympa~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-systems", rpm:"fusiondirectory-plugin-systems~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-user-reminder", rpm:"fusiondirectory-plugin-user-reminder~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-weblink", rpm:"fusiondirectory-plugin-weblink~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-webservice", rpm:"fusiondirectory-plugin-webservice~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-schema", rpm:"fusiondirectory-schema~1.3.1~1.2.mga8", rls:"MAGEIA8"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory", rpm:"fusiondirectory~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-database", rpm:"fusiondirectory-database~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-alias", rpm:"fusiondirectory-plugin-alias~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-applications", rpm:"fusiondirectory-plugin-applications~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-argonaut", rpm:"fusiondirectory-plugin-argonaut~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-audit", rpm:"fusiondirectory-plugin-audit~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-autofs", rpm:"fusiondirectory-plugin-autofs~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-certificates", rpm:"fusiondirectory-plugin-certificates~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-community", rpm:"fusiondirectory-plugin-community~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-cyrus", rpm:"fusiondirectory-plugin-cyrus~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-debconf", rpm:"fusiondirectory-plugin-debconf~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-developers", rpm:"fusiondirectory-plugin-developers~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dhcp", rpm:"fusiondirectory-plugin-dhcp~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dns", rpm:"fusiondirectory-plugin-dns~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dovecot", rpm:"fusiondirectory-plugin-dovecot~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-dsa", rpm:"fusiondirectory-plugin-dsa~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ejbca", rpm:"fusiondirectory-plugin-ejbca~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-fai", rpm:"fusiondirectory-plugin-fai~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-freeradius", rpm:"fusiondirectory-plugin-freeradius~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-fusioninventory", rpm:"fusiondirectory-plugin-fusioninventory~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-gpg", rpm:"fusiondirectory-plugin-gpg~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ipmi", rpm:"fusiondirectory-plugin-ipmi~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-kolab2", rpm:"fusiondirectory-plugin-kolab2~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ldapdump", rpm:"fusiondirectory-plugin-ldapdump~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ldapmanager", rpm:"fusiondirectory-plugin-ldapmanager~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-mail", rpm:"fusiondirectory-plugin-mail~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-mixedgroups", rpm:"fusiondirectory-plugin-mixedgroups~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-nagios", rpm:"fusiondirectory-plugin-nagios~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-netgroups", rpm:"fusiondirectory-plugin-netgroups~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-newsletter", rpm:"fusiondirectory-plugin-newsletter~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-opsi", rpm:"fusiondirectory-plugin-opsi~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-personal", rpm:"fusiondirectory-plugin-personal~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-posix", rpm:"fusiondirectory-plugin-posix~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ppolicy", rpm:"fusiondirectory-plugin-ppolicy~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-puppet", rpm:"fusiondirectory-plugin-puppet~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-pureftpd", rpm:"fusiondirectory-plugin-pureftpd~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-quota", rpm:"fusiondirectory-plugin-quota~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-renater-partage", rpm:"fusiondirectory-plugin-renater-partage~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-repository", rpm:"fusiondirectory-plugin-repository~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-samba", rpm:"fusiondirectory-plugin-samba~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sinaps", rpm:"fusiondirectory-plugin-sinaps~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sogo", rpm:"fusiondirectory-plugin-sogo~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-spamassassin", rpm:"fusiondirectory-plugin-spamassassin~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-squid", rpm:"fusiondirectory-plugin-squid~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-ssh", rpm:"fusiondirectory-plugin-ssh~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-subcontracting", rpm:"fusiondirectory-plugin-subcontracting~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sudo", rpm:"fusiondirectory-plugin-sudo~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-supann", rpm:"fusiondirectory-plugin-supann~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-sympa", rpm:"fusiondirectory-plugin-sympa~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-systems", rpm:"fusiondirectory-plugin-systems~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-user-reminder", rpm:"fusiondirectory-plugin-user-reminder~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-weblink", rpm:"fusiondirectory-plugin-weblink~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-plugin-webservice", rpm:"fusiondirectory-plugin-webservice~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"fusiondirectory-schema", rpm:"fusiondirectory-schema~1.3.1~1.2.mga9", rls:"MAGEIA9"))) {
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
