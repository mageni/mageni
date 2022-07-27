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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0454");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"Greenbone");
  script_tag(name:"severity_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");

  script_name("Mageia: Security Advisory (MGASA-2015-0454)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0454");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0454.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=16643");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/08/24/5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs-align-text, nodejs-ansi-regex, nodejs-camelcase, nodejs-center-align, nodejs-cliui, nodejs-code-point-at, nodejs-decamelize, nodejs-invert-kv, nodejs-is-buffer, nodejs-is-fullwidth-code-point, nodejs-kind-of, nodejs-lcid, nodejs-longest, nodejs-minimist, nodejs-number-is-nan, nodejs-os-locale, nodejs-repeat-string, nodejs-right-align, nodejs-source-map, nodejs-string-width, nodejs-strip-ansi, nodejs-window-size, nodejs-wrap-ansi, nodejs-y18n, nodejs-yargs, uglify-js' package(s) announced via the MGASA-2015-0454 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The UglifyJS node module has a problem where the combination of
De Morgan's Law and non-boolean values can lead to a case where code is
incorrectly minified, which can lead to possibly malicious minified JS
code.");

  script_tag(name:"affected", value:"'nodejs-align-text, nodejs-ansi-regex, nodejs-camelcase, nodejs-center-align, nodejs-cliui, nodejs-code-point-at, nodejs-decamelize, nodejs-invert-kv, nodejs-is-buffer, nodejs-is-fullwidth-code-point, nodejs-kind-of, nodejs-lcid, nodejs-longest, nodejs-minimist, nodejs-number-is-nan, nodejs-os-locale, nodejs-repeat-string, nodejs-right-align, nodejs-source-map, nodejs-string-width, nodejs-strip-ansi, nodejs-window-size, nodejs-wrap-ansi, nodejs-y18n, nodejs-yargs, uglify-js' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"js-uglify", rpm:"js-uglify~2.4.24~3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-align-text", rpm:"nodejs-align-text~0.1.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-ansi-regex", rpm:"nodejs-ansi-regex~2.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-camelcase", rpm:"nodejs-camelcase~1.2.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-center-align", rpm:"nodejs-center-align~0.1.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-cliui", rpm:"nodejs-cliui~3.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-code-point-at", rpm:"nodejs-code-point-at~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-decamelize", rpm:"nodejs-decamelize~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-invert-kv", rpm:"nodejs-invert-kv~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-is-buffer", rpm:"nodejs-is-buffer~1.1.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-is-fullwidth-code-point", rpm:"nodejs-is-fullwidth-code-point~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-kind-of", rpm:"nodejs-kind-of~2.0.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-lcid", rpm:"nodejs-lcid~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-longest", rpm:"nodejs-longest~1.0.1~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-minimist", rpm:"nodejs-minimist~1.2.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-number-is-nan", rpm:"nodejs-number-is-nan~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-os-locale", rpm:"nodejs-os-locale~1.4.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-repeat-string", rpm:"nodejs-repeat-string~1.5.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-right-align", rpm:"nodejs-right-align~0.1.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-source-map", rpm:"nodejs-source-map~0.5.1~1.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-string-width", rpm:"nodejs-string-width~1.0.1~6.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-strip-ansi", rpm:"nodejs-strip-ansi~3.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-window-size", rpm:"nodejs-window-size~0.1.2~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-wrap-ansi", rpm:"nodejs-wrap-ansi~1.0.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-y18n", rpm:"nodejs-y18n~3.2.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs-yargs", rpm:"nodejs-yargs~3.28.0~2.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"uglify-js", rpm:"uglify-js~2.4.24~3.mga5", rls:"MAGEIA5"))) {
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
