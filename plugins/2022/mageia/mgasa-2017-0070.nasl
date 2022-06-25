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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0070");
  script_cve_id("CVE-2016-9264", "CVE-2016-9265", "CVE-2016-9266", "CVE-2016-9827", "CVE-2016-9828", "CVE-2016-9829", "CVE-2016-9831");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-02-18 02:59:00 +0000 (Sat, 18 Feb 2017)");

  script_name("Mageia: Security Advisory (MGASA-2017-0070)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0070");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0070.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19751");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/11/10/9");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/11/10/10");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/11/10/11");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/05/2");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/05/3");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/05/4");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/12/05/6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ming' package(s) announced via the MGASA-2017-0070 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Global-buffer-overflow in printMP3Headers. (CVE-2016-9264)

Divide-by-zero in printMP3Headers. (CVE-2016-9265)

Left shift in listmp3.c. (CVE-2016-9266)

Heap-based buffer overflow in _iprintf. (CVE-2016-9827)

NULL pointer dereference in dumpBuffer. (CVE-2016-9828)

Heap-based buffer overflow in parseSWF_DEFINEFONT. (CVE-2016-9829)

Heap-based buffer overflow in parseSWF_RGBA. (CVE-2016-9831)");

  script_tag(name:"affected", value:"'ming' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64ming-devel", rpm:"lib64ming-devel~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64ming1", rpm:"lib64ming1~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libming-devel", rpm:"libming-devel~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libming1", rpm:"libming1~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ming", rpm:"ming~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ming-utils", rpm:"ming-utils~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"perl-SWF", rpm:"perl-SWF~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-SWF", rpm:"python-SWF~0.4.5~8.1.mga5", rls:"MAGEIA5"))) {
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
