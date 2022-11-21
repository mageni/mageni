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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0434");
  script_cve_id("CVE-2022-45060");
  script_tag(name:"creation_date", value:"2022-11-21 04:17:51 +0000 (Mon, 21 Nov 2022)");
  script_version("2022-11-21T04:17:51+0000");
  script_tag(name:"last_modification", value:"2022-11-21 04:17:51 +0000 (Mon, 21 Nov 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-09 19:49:00 +0000 (Wed, 09 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0434");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0434.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31121");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FJFEBVAZE52U2TMYLTOEW3F7YGVD7XQL/");
  script_xref(name:"URL", value:"https://docs.varnish-software.com/security/VSV00011/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'varnish' package(s) announced via the MGASA-2022-0434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An HTTP Request Forgery issue was discovered in Varnish Cache 5.x and 6.x
before 6.0.11, 7.x before 7.1.2, and 7.2.x before 7.2.1. An attacker may
introduce characters through HTTP/2 pseudo-headers that are invalid in the
context of an HTTP/1 request line, causing the Varnish server to produce
invalid HTTP/1 requests to the backend. This could, in turn, be used to
exploit vulnerabilities in a server behind the Varnish server.
(CVE-2022-45060)");

  script_tag(name:"affected", value:"'varnish' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish-devel", rpm:"lib64varnish-devel~6.5.1~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64varnish2", rpm:"lib64varnish2~6.5.1~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish-devel", rpm:"libvarnish-devel~6.5.1~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libvarnish2", rpm:"libvarnish2~6.5.1~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"varnish", rpm:"varnish~6.5.1~1.3.mga8", rls:"MAGEIA8"))) {
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
