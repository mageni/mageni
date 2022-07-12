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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0196");
  script_cve_id("CVE-2015-7503");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-05 21:23:00 +0000 (Sun, 05 Nov 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0196)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0196");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0196.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18259");
  script_xref(name:"URL", value:"http://framework.zend.com/security/advisory/ZF2015-10");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'php-ZendFramework2' package(s) announced via the MGASA-2016-0196 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated php-ZendFramework2 packages fix security vulnerability:

Zend\Crypt\PublicKey\Rsa\PublicKey has a call to openssl_public_encrypt() which
uses PHP's default $padding argument, which specifies OPENSSL_PKCS1_PADDING,
indicating usage of PKCS1v1.5 padding. This padding has a known vulnerability,
the Bleichenbacher's chosen-ciphertext attack, which can be used to decrypt
arbitrary ciphertexts (CVE-2015-7503).");

  script_tag(name:"affected", value:"'php-ZendFramework2' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2", rpm:"php-ZendFramework2~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Authentication", rpm:"php-ZendFramework2-Authentication~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Barcode", rpm:"php-ZendFramework2-Barcode~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Cache", rpm:"php-ZendFramework2-Cache~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Captcha", rpm:"php-ZendFramework2-Captcha~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Code", rpm:"php-ZendFramework2-Code~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Config", rpm:"php-ZendFramework2-Config~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Console", rpm:"php-ZendFramework2-Console~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Crypt", rpm:"php-ZendFramework2-Crypt~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Db", rpm:"php-ZendFramework2-Db~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Debug", rpm:"php-ZendFramework2-Debug~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Di", rpm:"php-ZendFramework2-Di~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Dom", rpm:"php-ZendFramework2-Dom~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Escaper", rpm:"php-ZendFramework2-Escaper~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-EventManager", rpm:"php-ZendFramework2-EventManager~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Feed", rpm:"php-ZendFramework2-Feed~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-File", rpm:"php-ZendFramework2-File~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Filter", rpm:"php-ZendFramework2-Filter~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Form", rpm:"php-ZendFramework2-Form~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Http", rpm:"php-ZendFramework2-Http~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-I18n", rpm:"php-ZendFramework2-I18n~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-InputFilter", rpm:"php-ZendFramework2-InputFilter~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Json", rpm:"php-ZendFramework2-Json~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Ldap", rpm:"php-ZendFramework2-Ldap~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Loader", rpm:"php-ZendFramework2-Loader~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Log", rpm:"php-ZendFramework2-Log~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Mail", rpm:"php-ZendFramework2-Mail~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Math", rpm:"php-ZendFramework2-Math~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Memory", rpm:"php-ZendFramework2-Memory~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Mime", rpm:"php-ZendFramework2-Mime~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-ModuleManager", rpm:"php-ZendFramework2-ModuleManager~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Mvc", rpm:"php-ZendFramework2-Mvc~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Navigation", rpm:"php-ZendFramework2-Navigation~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Paginator", rpm:"php-ZendFramework2-Paginator~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Permissions-Acl", rpm:"php-ZendFramework2-Permissions-Acl~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Permissions-Rbac", rpm:"php-ZendFramework2-Permissions-Rbac~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-ProgressBar", rpm:"php-ZendFramework2-ProgressBar~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Serializer", rpm:"php-ZendFramework2-Serializer~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Server", rpm:"php-ZendFramework2-Server~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-ServiceManager", rpm:"php-ZendFramework2-ServiceManager~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Session", rpm:"php-ZendFramework2-Session~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Soap", rpm:"php-ZendFramework2-Soap~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Stdlib", rpm:"php-ZendFramework2-Stdlib~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Tag", rpm:"php-ZendFramework2-Tag~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Test", rpm:"php-ZendFramework2-Test~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Text", rpm:"php-ZendFramework2-Text~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Uri", rpm:"php-ZendFramework2-Uri~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Validator", rpm:"php-ZendFramework2-Validator~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-Version", rpm:"php-ZendFramework2-Version~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-View", rpm:"php-ZendFramework2-View~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-XmlRpc", rpm:"php-ZendFramework2-XmlRpc~2.4.9~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"php-ZendFramework2-ZendXml", rpm:"php-ZendFramework2-ZendXml~2.4.9~1.mga5", rls:"MAGEIA5"))) {
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
