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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0389");
  script_cve_id("CVE-2021-25287", "CVE-2021-25288", "CVE-2021-28675", "CVE-2021-28676", "CVE-2021-28677", "CVE-2021-28678", "CVE-2021-34552");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-16 12:28:00 +0000 (Fri, 16 Jul 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0389)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0389");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0389.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29002");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pillow' package(s) announced via the MGASA-2021-0389 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated python-pillow packages fix security vulnerabilities:

An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds
read in J2kDecode, in j2ku_graya_la (CVE-2021-25287).

An issue was discovered in Pillow before 8.2.0. There is an out-of-bounds
read in J2kDecode, in j2ku_gray_i (CVE-2021-25288).

An issue was discovered in Pillow before 8.2.0. PSDImagePlugin.PsdImageFile
lacked a sanity check on the number of input layers relative to the size of
the data block. This could lead to a DoS on Image.open prior to Image.load
(CVE-2021-28675).

An issue was discovered in Pillow before 8.2.0. For FLI data, FliDecode did
not properly check that the block advance was non-zero, potentially leading
to an infinite loop on load (CVE-2021-28676).

An issue was discovered in Pillow before 8.2.0. For EPS data, the readline
implementation used in EPSImageFile has to deal with any combination of \r
and \n as line endings. It used an accidentally quadratic method of
accumulating lines while looking for a line ending. A malicious EPS file
could use this to perform a DoS of Pillow in the open phase, before an
image was accepted for opening (CVE-2021-28677).

An issue was discovered in Pillow before 8.2.0. For BLP data, BlpImagePlugin
did not properly check that reads (after jumping to file offsets) returned
data. This could lead to a DoS where the decoder could be run a large number
of times on empty data (CVE-2021-28678).

Pillow through 8.2.0 and PIL (aka Python Imaging Library) through 1.1.7
allow an attacker to pass controlled parameters directly into a convert
function to trigger a buffer overflow in Convert.c (CVE-2021-34552).");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~8.1.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow", rpm:"python3-pillow~8.1.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-devel", rpm:"python3-pillow-devel~8.1.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-doc", rpm:"python3-pillow-doc~8.1.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-qt", rpm:"python3-pillow-qt~8.1.2~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-tk", rpm:"python3-pillow-tk~8.1.2~1.mga8", rls:"MAGEIA8"))) {
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
