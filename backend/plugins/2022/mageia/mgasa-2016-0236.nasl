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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0236");
  script_cve_id("CVE-2016-2365", "CVE-2016-2366", "CVE-2016-2367", "CVE-2016-2368", "CVE-2016-2369", "CVE-2016-2370", "CVE-2016-2371", "CVE-2016-2372", "CVE-2016-2373", "CVE-2016-2374", "CVE-2016-2375", "CVE-2016-2376", "CVE-2016-2377", "CVE-2016-2378", "CVE-2016-2380", "CVE-2016-4323");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-30 01:59:00 +0000 (Thu, 30 Mar 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0236)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0236");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0236.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=18754");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0118");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0119");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0120");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0123");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0128");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0133");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0134");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0135");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0136");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0137");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0138");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0139");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0140");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0141");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0142");
  script_xref(name:"URL", value:"http://www.talosintel.com/reports/TALOS-2016-0143");
  script_xref(name:"URL", value:"https://bitbucket.org/pidgin/www/src/tip/htdocs/ChangeLog?fileviewer=file-view-default");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pidgin' package(s) announced via the MGASA-2016-0236 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflows vulnerability exists in the handling of the MXIT
protocol in Pidgin. Specially crafted MXIT data sent from the server could
potentially result in arbitrary code execution. A malicious server or an
attacker who intercepts the network traffic can send an invalid size for a
packet which will trigger a buffer overflow (CVE-2016-2376).

A buffer vulnerability exists in the handling of the MXIT protocol in
Pidgin. Specially crafted MXIT data sent by the server could potentially
result in an out of bounds write of one byte. A malicious server can send
a negative content-length in response to a HTTP request triggering the
vulnerability (CVE-2016-2377).

A buffer overflow vulnerability exists in the handling of the MXIT
protocol Pidgin. Specially crafted data sent via the server could
potentially result in a buffer overflow, potentially resulting in memory
corruption. A malicious server or an unfiltered malicious user can send
negative length values to trigger this vulnerability (CVE-2016-2378).

An information leak exists in the handling of the MXIT protocol in Pidgin.
Specially crafted MXIT data sent to the server could potentially result in
an out of bounds read. A user could be convinced to enter a particular
string which would then get converted incorrectly and could lead to a
potential out-of-bounds read (CVE-2016-2380).

A directory traversal exists in the handling of the MXIT protocol in
Pidgin. Specially crafted MXIT data sent from the server could potentially
result in an overwrite of files. A malicious server or someone with access
to the network traffic can provide an invalid filename for a splash image
triggering the vulnerability (CVE-2016-4323).

A denial of service vulnerability exists in the handling of the MXIT
protocol in Pidgin. Specially crafted MXIT data sent via the server could
potentially result in a null pointer dereference. A malicious server or an
attacker who intercepts the network traffic can send invalid data to
trigger this vulnerability and cause a crash (CVE-2016-2365).

A denial of service vulnerability exists in the handling of the MXIT
protocol in Pidgin. Specially crafted MXIT data sent via the server could
potentially result in an out-of-bounds read. A malicious server or an
attacker who intercepts the network traffic can send invalid data to
trigger this vulnerability and cause a crash (CVE-2016-2366).

An information leak exists in the handling of the MXIT protocol in Pidgin.
Specially crafted MXIT data sent via the server could potentially result
in an out of bounds read. A malicious user, server, or man-in-the-middle
can send an invalid size for an avatar which will trigger an out-of-bounds
read vulnerability. This could result in a denial of service or copy data
from memory to the file, resulting in an information leak if the avatar is
sent to another user (CVE-2016-2367).

Multiple memory corruption vulnerabilities ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'pidgin' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"finch", rpm:"finch~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64finch0", rpm:"lib64finch0~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64purple-devel", rpm:"lib64purple-devel~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64purple0", rpm:"lib64purple0~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libfinch0", rpm:"libfinch0~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpurple0", rpm:"libpurple0~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-bonjour", rpm:"pidgin-bonjour~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-client", rpm:"pidgin-client~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-i18n", rpm:"pidgin-i18n~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-meanwhile", rpm:"pidgin-meanwhile~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-plugins", rpm:"pidgin-plugins~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-silc", rpm:"pidgin-silc~2.11.0~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pidgin-tcl", rpm:"pidgin-tcl~2.11.0~1.mga5", rls:"MAGEIA5"))) {
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
