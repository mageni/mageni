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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0434");
  script_cve_id("CVE-2020-10177", "CVE-2020-10378", "CVE-2020-10994", "CVE-2020-11538");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 19:15:00 +0000 (Mon, 27 Jul 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0434)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0434");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0434.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26919");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/HOKHNWV2VS5GESY7IBD237E7C6T3I427/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-pillow' package(s) announced via the MGASA-2020-0434 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Pillow before 6.2.3 and 7.x before 7.0.1 has multiple out-of-bounds reads in
libImaging/FliDecode.c (CVE-2020-10177).

In libImaging/PcxDecode.c in Pillow before 6.2.3 and 7.x before 7.0.1, an
out-of-bounds read can occur when reading PCX files where state->shuffle is
instructed to read beyond state->buffer (CVE-2020-10378).

An out-of-bounds read flaw was found in python-pillow in the way JP2 images are
parsed. An application that uses python-pillow to decode untrusted images may
be vulnerable to this issue. This flaw allows an attacker to read data. The
highest threat from this vulnerability is to confidentiality (CVE-2020-10994).

An out-of-bounds read/write flaw was found in python-pillow, in the way SGI RLE
images are decoded. An application that uses python-pillow to decode untrusted
images may be vulnerable. This flaw allows an attacker to crash the application
or potentially execute code on the system. The highest threat from this
vulnerability is to data confidentiality and integrity as well as system
availability (CVE-2020-11538).

Also, python-pillow is now built with OpenJPEG2000 image support.");

  script_tag(name:"affected", value:"'python-pillow' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-pillow", rpm:"python-pillow~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow", rpm:"python2-pillow~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-devel", rpm:"python2-pillow-devel~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-doc", rpm:"python2-pillow-doc~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-qt", rpm:"python2-pillow-qt~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pillow-tk", rpm:"python2-pillow-tk~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow", rpm:"python3-pillow~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-devel", rpm:"python3-pillow-devel~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-doc", rpm:"python3-pillow-doc~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-qt", rpm:"python3-pillow-qt~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pillow-tk", rpm:"python3-pillow-tk~5.4.1~1.3.mga7", rls:"MAGEIA7"))) {
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
