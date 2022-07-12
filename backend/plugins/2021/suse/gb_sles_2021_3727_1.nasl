# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.3727.1");
  script_cve_id("CVE-2021-21703");
  script_tag(name:"creation_date", value:"2021-11-21 03:21:15 +0000 (Sun, 21 Nov 2021)");
  script_version("2021-11-21T03:21:15+0000");
  script_tag(name:"last_modification", value:"2021-11-21 03:21:15 +0000 (Sun, 21 Nov 2021)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-03 16:22:00 +0000 (Wed, 03 Nov 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:3727-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:3727-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20213727-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php72' package(s) announced via the SUSE-SU-2021:3727-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for php72 fixes the following issues:

CVE-2021-21703: Fixed local privilege escalation via PHP-FPM
 (bsc#1192050).");

  script_tag(name:"affected", value:"'php72' package(s) on SUSE Linux Enterprise Module for Web Scripting 12, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0") {

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php72", rpm:"apache2-mod_php72~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"apache2-mod_php72-debuginfo", rpm:"apache2-mod_php72-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72", rpm:"php72~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-bcmath", rpm:"php72-bcmath~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-bcmath-debuginfo", rpm:"php72-bcmath-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-bz2", rpm:"php72-bz2~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-bz2-debuginfo", rpm:"php72-bz2-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-calendar", rpm:"php72-calendar~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-calendar-debuginfo", rpm:"php72-calendar-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-ctype", rpm:"php72-ctype~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-ctype-debuginfo", rpm:"php72-ctype-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-curl", rpm:"php72-curl~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-curl-debuginfo", rpm:"php72-curl-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-dba", rpm:"php72-dba~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-dba-debuginfo", rpm:"php72-dba-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-debuginfo", rpm:"php72-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-debugsource", rpm:"php72-debugsource~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-dom", rpm:"php72-dom~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-dom-debuginfo", rpm:"php72-dom-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-enchant", rpm:"php72-enchant~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-enchant-debuginfo", rpm:"php72-enchant-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-exif", rpm:"php72-exif~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-exif-debuginfo", rpm:"php72-exif-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-fastcgi", rpm:"php72-fastcgi~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-fastcgi-debuginfo", rpm:"php72-fastcgi-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-fileinfo", rpm:"php72-fileinfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-fileinfo-debuginfo", rpm:"php72-fileinfo-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-fpm", rpm:"php72-fpm~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-fpm-debuginfo", rpm:"php72-fpm-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-ftp", rpm:"php72-ftp~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-ftp-debuginfo", rpm:"php72-ftp-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-gd", rpm:"php72-gd~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-gd-debuginfo", rpm:"php72-gd-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-gettext", rpm:"php72-gettext~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-gettext-debuginfo", rpm:"php72-gettext-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-gmp", rpm:"php72-gmp~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-gmp-debuginfo", rpm:"php72-gmp-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-iconv", rpm:"php72-iconv~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-iconv-debuginfo", rpm:"php72-iconv-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-imap", rpm:"php72-imap~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-imap-debuginfo", rpm:"php72-imap-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-intl", rpm:"php72-intl~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-intl-debuginfo", rpm:"php72-intl-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-json", rpm:"php72-json~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-json-debuginfo", rpm:"php72-json-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-ldap", rpm:"php72-ldap~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-ldap-debuginfo", rpm:"php72-ldap-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-mbstring", rpm:"php72-mbstring~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-mbstring-debuginfo", rpm:"php72-mbstring-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-mysql", rpm:"php72-mysql~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-mysql-debuginfo", rpm:"php72-mysql-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-odbc", rpm:"php72-odbc~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-odbc-debuginfo", rpm:"php72-odbc-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-opcache", rpm:"php72-opcache~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-opcache-debuginfo", rpm:"php72-opcache-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-openssl", rpm:"php72-openssl~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-openssl-debuginfo", rpm:"php72-openssl-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pcntl", rpm:"php72-pcntl~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pcntl-debuginfo", rpm:"php72-pcntl-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pdo", rpm:"php72-pdo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pdo-debuginfo", rpm:"php72-pdo-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pear", rpm:"php72-pear~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pear-Archive_Tar", rpm:"php72-pear-Archive_Tar~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pgsql", rpm:"php72-pgsql~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pgsql-debuginfo", rpm:"php72-pgsql-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-phar", rpm:"php72-phar~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-phar-debuginfo", rpm:"php72-phar-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-posix", rpm:"php72-posix~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-posix-debuginfo", rpm:"php72-posix-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pspell", rpm:"php72-pspell~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-pspell-debuginfo", rpm:"php72-pspell-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-readline", rpm:"php72-readline~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-readline-debuginfo", rpm:"php72-readline-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-shmop", rpm:"php72-shmop~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-shmop-debuginfo", rpm:"php72-shmop-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-snmp", rpm:"php72-snmp~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-snmp-debuginfo", rpm:"php72-snmp-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-soap", rpm:"php72-soap~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-soap-debuginfo", rpm:"php72-soap-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sockets", rpm:"php72-sockets~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sockets-debuginfo", rpm:"php72-sockets-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sodium", rpm:"php72-sodium~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sodium-debuginfo", rpm:"php72-sodium-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sqlite", rpm:"php72-sqlite~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sqlite-debuginfo", rpm:"php72-sqlite-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sysvmsg", rpm:"php72-sysvmsg~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sysvmsg-debuginfo", rpm:"php72-sysvmsg-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sysvsem", rpm:"php72-sysvsem~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sysvsem-debuginfo", rpm:"php72-sysvsem-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sysvshm", rpm:"php72-sysvshm~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-sysvshm-debuginfo", rpm:"php72-sysvshm-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-tidy", rpm:"php72-tidy~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-tidy-debuginfo", rpm:"php72-tidy-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-tokenizer", rpm:"php72-tokenizer~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-tokenizer-debuginfo", rpm:"php72-tokenizer-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-wddx", rpm:"php72-wddx~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-wddx-debuginfo", rpm:"php72-wddx-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xmlreader", rpm:"php72-xmlreader~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xmlreader-debuginfo", rpm:"php72-xmlreader-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xmlrpc", rpm:"php72-xmlrpc~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xmlrpc-debuginfo", rpm:"php72-xmlrpc-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xmlwriter", rpm:"php72-xmlwriter~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xmlwriter-debuginfo", rpm:"php72-xmlwriter-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xsl", rpm:"php72-xsl~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-xsl-debuginfo", rpm:"php72-xsl-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-zip", rpm:"php72-zip~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-zip-debuginfo", rpm:"php72-zip-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-zlib", rpm:"php72-zlib~7.2.5~1.72.1", rls:"SLES12.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php72-zlib-debuginfo", rpm:"php72-zlib-debuginfo~7.2.5~1.72.1", rls:"SLES12.0"))) {
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
