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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0162");
  script_cve_id("CVE-2016-10140", "CVE-2016-10201", "CVE-2016-10202", "CVE-2016-10203", "CVE-2016-10204", "CVE-2016-10205", "CVE-2016-10206", "CVE-2017-5367", "CVE-2017-5368", "CVE-2017-5595", "CVE-2017-7203");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-07 12:58:00 +0000 (Tue, 07 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0162)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0162");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0162.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20215");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/releases/tag/1.30.2");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/releases");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/commit/c5906a5d4f9adc7bdaabcf035fe223997883018b");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/pull/1764");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/pull/1764");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/commit/ea5342abd2ef3b7dfb1b05e59ccf420196264340");
  script_xref(name:"URL", value:"https://github.com/ZoneMinder/ZoneMinder/commit/8b19fca9927cdec07cc9dd09bdcf2496a5ae69b3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl-Sys-MemInfo, zoneminder' package(s) announced via the MGASA-2017-0162 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issues:

Information disclosure and authentication bypass vulnerability exists in
the Apache HTTP Server configuration bundled with ZoneMinder v1.30 and
v1.29, which allows a remote unauthenticated attacker to browse all
directories in the web root, e.g., a remote unauthenticated attacker can
view all CCTV images on the server via the /events URI. (CVE-2016-10140)

Cross-site scripting (XSS) vulnerability in Zoneminder 1.30 and earlier
allows remote attackers to inject arbitrary web script or HTML via the
format parameter in a download log request to index.php. (CVE-2016-10201)

Cross-site scripting (XSS) vulnerability in Zoneminder 1.30 and earlier
allows remote attackers to inject arbitrary web script or HTML via the
path info to index.php. (CVE-2016-10202)

Cross-site scripting (XSS) vulnerability in Zoneminder 1.30 and earlier
allows remote attackers to inject arbitrary web script or HTML via the
name when creating a new monitor. (CVE-2016-10203)

SQL injection vulnerability in Zoneminder 1.30 and earlier allows remote
attackers to execute arbitrary SQL commands via the limit parameter in a
log query request to index.php. (CVE-2016-10204)

Session fixation vulnerability in Zoneminder 1.30 and earlier allows
remote attackers to hijack web sessions via the ZMSESSID cookie.
(CVE-2016-10205)

Cross-site request forgery (CSRF) vulnerability in Zoneminder 1.30 and
earlier allows remote attackers to hijack the authentication of users for
requests that change passwords and possibly have unspecified other impact
as demonstrated by a crafted user action request to index.php.
(CVE-2016-10206)

Multiple reflected XSS vulnerabilities exist within form and link input
parameters of ZoneMinder v1.30 and v1.29, an open-source CCTV server web
application, which allows a remote attacker to execute malicious scripts
within an authenticated client's browser. The URL is /zm/index.php and
sample parameters could include action=login&view=postlogin[XSS]
view=console[XSS] view=groups[XSS]
view=events&filter[terms][1][cnj]=and[XSS]
view=events&filter%5Bterms%5D%5B1%5D%5Bcnj%5D=and[XSS]
view=events&filter%5Bterms%5D%5B1%5D%5Bcnj%5D=[XSS]and
view=events&limit=1%22%3E%3C/a%3E[XSS] (among others). (CVE-2017-5367)

ZoneMinder v1.30 and v1.29, an open-source CCTV server web application, is
vulnerable to CSRF (Cross Site Request Forgery) which allows a remote
attack to make changes to the web application as the current logged in
victim. If the victim visits a malicious web page, the attacker can
silently and automatically create a new admin user within the web
application for remote persistence and further attacks. The URL is
/zm/index.php and sample parameters could include action=user uid=0
newUser[Username]=attacker1 newUser[Password]=Password1234
conf_password=Password1234 newUser[System]=Edit (among others).
(CVE-2017-5368)

A file disclosure and ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'perl-Sys-MemInfo, zoneminder' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"perl-Sys-MemInfo", rpm:"perl-Sys-MemInfo~0.910.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zoneminder", rpm:"zoneminder~1.30.4~1.1.mga5", rls:"MAGEIA5"))) {
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
