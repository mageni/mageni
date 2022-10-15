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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0367");
  script_cve_id("CVE-2015-20107", "CVE-2021-4189", "CVE-2022-0391");
  script_tag(name:"creation_date", value:"2022-10-14 04:46:38 +0000 (Fri, 14 Oct 2022)");
  script_version("2022-10-14T04:46:38+0000");
  script_tag(name:"last_modification", value:"2022-10-14 04:46:38 +0000 (Fri, 14 Oct 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-04-21 13:39:00 +0000 (Thu, 21 Apr 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0367)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0367");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0367.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30572");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/UIOJUZ5JMEMGSKNISTOVI4PDP36FDL5Y/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/Y4E2WBEJ42CGLGDHD6ZXOLZ2W6G3YOVD/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/W5664BGZVTA46LQDNTYX5THG6CN4FYJX/");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5519-1");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2022-October/012483.html");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AOHEWJI4EPENRFNUSCXL2KZG7QSBH2MJ/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python' package(s) announced via the MGASA-2022-0367 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The mailcap module does not add escape characters into commands discovered
in the system mailcap file. (CVE-2015-20107)
Allows an attacker to set up a malicious FTP server that can trick FTP
clients into connecting back to a given IP address and port.
(CVE-2021-4189)
The urlparse method does not sanitize input and allows characters like
'\r' and '\n' in the URL path. This flaw allows an attacker to input a
crafted URL, leading to injection attacks. (CVE-2022-0391)");

  script_tag(name:"affected", value:"'python' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64python-devel", rpm:"lib64python-devel~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7", rpm:"lib64python2.7~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-stdlib", rpm:"lib64python2.7-stdlib~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64python2.7-testsuite", rpm:"lib64python2.7-testsuite~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython-devel", rpm:"libpython-devel~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7", rpm:"libpython2.7~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-stdlib", rpm:"libpython2.7-stdlib~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libpython2.7-testsuite", rpm:"libpython2.7-testsuite~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python", rpm:"python~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"tkinter-apps", rpm:"tkinter-apps~2.7.18~7.5.mga8", rls:"MAGEIA8"))) {
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
