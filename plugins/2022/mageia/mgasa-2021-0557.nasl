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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0557");
  script_cve_id("CVE-2020-28200", "CVE-2021-29157", "CVE-2021-33515");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-18 06:15:00 +0000 (Sun, 18 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0557)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0557");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0557.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29160");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000460.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000461.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000462.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000459.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-June/000457.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-October/000465.html");
  script_xref(name:"URL", value:"https://dovecot.org/pipermail/dovecot-news/2021-December/000468.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dovecot' package(s) announced via the MGASA-2021-0557 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated dovecot packages fix security vulnerabilities:

The Sieve engine in Dovecot before 2.3.15 allows Uncontrolled Resource
Consumption, as demonstrated by a situation with a complex regular
expression for the regex extension (CVE-2020-28200).

Dovecot before 2.3.15 allows ../ Path Traversal. An attacker with access
to the local filesystem can trick OAuth2 authentication into using an HS256
validation key from an attacker-controlled location. This occurs during use
of local JWT validation with the posix fs driver (CVE-2021-29157).

The submission service in Dovecot before 2.3.15 allows STARTTLS command
injection in lib-smtp. Sensitive information can be redirected to an
attacker-controlled address (CVE-2021-33515).");

  script_tag(name:"affected", value:"'dovecot' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"dovecot", rpm:"dovecot~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-devel", rpm:"dovecot-devel~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole", rpm:"dovecot-pigeonhole~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-pigeonhole-devel", rpm:"dovecot-pigeonhole-devel~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-gssapi", rpm:"dovecot-plugins-gssapi~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-ldap", rpm:"dovecot-plugins-ldap~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-mysql", rpm:"dovecot-plugins-mysql~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-pgsql", rpm:"dovecot-plugins-pgsql~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"dovecot-plugins-sqlite", rpm:"dovecot-plugins-sqlite~2.3.17.1~1.1.mga8", rls:"MAGEIA8"))) {
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
