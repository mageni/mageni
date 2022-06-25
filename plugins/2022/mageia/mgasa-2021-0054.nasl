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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0054");
  script_cve_id("CVE-2019-20916", "CVE-2020-26137");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-03-15 16:18:00 +0000 (Mon, 15 Mar 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0054)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0054");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0054.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27301");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27407");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4601-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-4570-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pip' package(s) announced via the MGASA-2021-0054 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that pip did not properly sanitize the filename during pip
install. A remote attacker could possible use this issue to read and write
arbitrary files on the host filesystem as root, resulting in a directory
traversal attack (CVE-2019-20916).

urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP
request method, as demonstrated by inserting CR and LF control characters in
the first argument of putrequest(). The python-pip package bundles a copy of
python-urllib3, which was affected by this issue. The bundled copy was
patched to fix the issue (CVE-2020-26137).");

  script_tag(name:"affected", value:"'python-pip' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"python-pip", rpm:"python-pip~19.0.3~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pip-wheel", rpm:"python-pip-wheel~19.0.3~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pip", rpm:"python2-pip~19.0.3~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pip", rpm:"python3-pip~19.0.3~1.3.mga7", rls:"MAGEIA7"))) {
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
