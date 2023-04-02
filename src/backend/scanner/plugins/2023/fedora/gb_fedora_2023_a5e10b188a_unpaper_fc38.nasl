# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.827292");
  script_version("2023-03-16T10:09:04+0000");
  script_cve_id("CVE-2023-0927", "CVE-2023-0928", "CVE-2023-0929", "CVE-2023-0930", "CVE-2023-0931", "CVE-2023-0932", "CVE-2023-0933", "CVE-2023-0941", "CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216", "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220", "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224", "CVE-2023-1225", "CVE-2023-1226", "CVE-2023-1227");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-16 10:09:04 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-14 02:08:00 +0000 (Tue, 14 Mar 2023)");
  script_name("Fedora: Security Advisory for unpaper (FEDORA-2023-a5e10b188a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-a5e10b188a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CCVH4VLBERYPB45PH3RBHKS5D44RFVKG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'unpaper'
  package(s) announced via the FEDORA-2023-a5e10b188a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"unpaper is a post-processing tool for scanned sheets of paper, especially for
book pages that have been scanned from previously created photocopies. The
main purpose is to make scanned book pages better readable on screen after
conversion to PDF. Additionally, unpaper might be useful to enhance the
quality of scanned pages before performing optical character recognition (OCR).

unpaper tries to clean scanned images by removing dark edges that appeared
through scanning or copying on areas outside the actual page content (e.g. dark
areas between the left-hand-side and the right-hand-side of a double-sided
book-page scan).

The program also tries to detect misaligned centering and rotation of pages
and will automatically straighten each page by rotating it to the correct
angle. This process is called 'deskewing'.");

  script_tag(name:"affected", value:"'unpaper' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"unpaper", rpm:"unpaper~7.0.0~7.fc38", rls:"FC38"))) {
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