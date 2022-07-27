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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2019.0242");
  script_cve_id("CVE-2019-10181", "CVE-2019-10182", "CVE-2019-10185");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-13 14:58:00 +0000 (Tue, 13 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2019-0242)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(6|7)");

  script_xref(name:"Advisory-ID", value:"MGASA-2019-0242");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2019-0242.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=25228");
  script_xref(name:"URL", value:"https://access.redhat.com/errata/RHSA-2019:2003");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2019/07/31/2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web, icedtea-web' package(s) announced via the MGASA-2019-0242 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated icedtea-web packages fix security vulnerabilities:

It was found that in icedtea-web up to and including 1.7.2 and 1.8.2
executable code could be injected in a JAR file without compromising the
signature verification. An attacker could use this flaw to inject code in
a trusted JAR. The code would be executed inside the sandbox.
(CVE-2019-10181)

It was found that icedtea-web though 1.7.2 and 1.8.2 did not properly
sanitize paths from <jar/> elements in JNLP files. An attacker could trick
a victim into running a specially crafted application and use this flaw to
upload arbitrary files to arbitrary locations in the context of the user.
(CVE-2019-10182)

It was found that icedtea-web up to and including 1.7.2 and 1.8.2 was
vulnerable to a zip-slip attack during auto-extraction of a JAR file.
An attacker could use this flaw to write files to arbitrary locations.
This could also be used to replace the main running application and,
possibly, break out of the sandbox. (CVE-2019-10185)");

  script_tag(name:"affected", value:"'icedtea-web, icedtea-web' package(s) on Mageia 6, Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.7.2~4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-devel", rpm:"icedtea-web-devel~1.7.2~4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.7.2~4.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.8~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-devel", rpm:"icedtea-web-devel~1.8~2.1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.8~2.1.mga7", rls:"MAGEIA7"))) {
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
