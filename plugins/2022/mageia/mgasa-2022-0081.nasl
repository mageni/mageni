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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0081");
  script_cve_id("CVE-2022-25235", "CVE-2022-25236", "CVE-2022-25313", "CVE-2022-25314", "CVE-2022-25315");
  script_tag(name:"creation_date", value:"2022-02-23 03:14:32 +0000 (Wed, 23 Feb 2022)");
  script_version("2022-02-25T03:26:47+0000");
  script_tag(name:"last_modification", value:"2022-02-25 03:26:47 +0000 (Fri, 25 Feb 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 20:55:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0081)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0081");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0081.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30070");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2022/q1/150");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5288-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'expat' package(s) announced via the MGASA-2022-0081 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Passing malformed 2- and 3-byte UTF-8 sequences (e.g. from start tag names)
to the XML processing application on top of Expat can cause arbitrary
damage (e.g. code execution) depending on how invalid UTF-8 is handled
inside the XML processor, validation was not their job but Expat's.
Exploits with code execution are known to exist. (CVE-2022-25235)

Passing (one or more) namespace separator characters in 'xmlns[:prefix]'
attribute values made Expat send malformed tag names to the XML processor
on top of Expat which can cause arbitrary damage (e.g. code execution)
depending on such unexpectable cases are handled inside the XML processor,
validation was not their job but Expat's. Exploits with code execution
are known to exist. (CVE-2022-25236)

Fix stack exhaustion in doctype parsing that could be triggered by e.g. a
2 megabytes file with a large number of opening braces. Expected impact
is denial of service or potentially arbitrary code execution.
(CVE-2022-25313)

Fix integer overflow in function copyString, only affects the encoding
name parameter at parser creation time which is often hardcoded (rather
than user input), takes a value in the gigabytes to trigger, and a 64-bit
machine. Expected impact is denial of service. (CVE-2022-25314)

Fix integer overflow in function storeRawNames, needs input in the
gigabytes and a 64-bit machine. Expected impact is denial of service or
potentially arbitrary code execution. (CVE-2022-25315)");

  script_tag(name:"affected", value:"'expat' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"expat", rpm:"expat~2.2.10~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat-devel", rpm:"lib64expat-devel~2.2.10~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64expat1", rpm:"lib64expat1~2.2.10~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat-devel", rpm:"libexpat-devel~2.2.10~1.3.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libexpat1", rpm:"libexpat1~2.2.10~1.3.mga8", rls:"MAGEIA8"))) {
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
