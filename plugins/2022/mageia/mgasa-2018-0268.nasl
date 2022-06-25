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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0268");
  script_cve_id("CVE-2017-11215", "CVE-2017-11225", "CVE-2018-6056", "CVE-2018-6057", "CVE-2018-6060", "CVE-2018-6061", "CVE-2018-6062", "CVE-2018-6063", "CVE-2018-6064", "CVE-2018-6065", "CVE-2018-6066", "CVE-2018-6067", "CVE-2018-6068", "CVE-2018-6069", "CVE-2018-6070", "CVE-2018-6071", "CVE-2018-6072", "CVE-2018-6073", "CVE-2018-6074", "CVE-2018-6075", "CVE-2018-6076", "CVE-2018-6077", "CVE-2018-6078", "CVE-2018-6079", "CVE-2018-6080", "CVE-2018-6081", "CVE-2018-6082", "CVE-2018-6083", "CVE-2018-6084", "CVE-2018-6085", "CVE-2018-6086", "CVE-2018-6087", "CVE-2018-6088", "CVE-2018-6089", "CVE-2018-6090", "CVE-2018-6091", "CVE-2018-6092", "CVE-2018-6093", "CVE-2018-6094", "CVE-2018-6095", "CVE-2018-6096", "CVE-2018-6097", "CVE-2018-6098", "CVE-2018-6099", "CVE-2018-6100", "CVE-2018-6101", "CVE-2018-6102", "CVE-2018-6103", "CVE-2018-6104", "CVE-2018-6105", "CVE-2018-6106", "CVE-2018-6107", "CVE-2018-6108", "CVE-2018-6109", "CVE-2018-6110", "CVE-2018-6111", "CVE-2018-6112", "CVE-2018-6113", "CVE-2018-6114", "CVE-2018-6115", "CVE-2018-6116", "CVE-2018-6117", "CVE-2018-6118", "CVE-2018-6120", "CVE-2018-6121", "CVE-2018-6122", "CVE-2018-6123", "CVE-2018-6124", "CVE-2018-6126", "CVE-2018-6127", "CVE-2018-6128", "CVE-2018-6129", "CVE-2018-6130", "CVE-2018-6131", "CVE-2018-6132", "CVE-2018-6133", "CVE-2018-6134", "CVE-2018-6135", "CVE-2018-6136", "CVE-2018-6137", "CVE-2018-6138", "CVE-2018-6139", "CVE-2018-6140", "CVE-2018-6141", "CVE-2018-6142", "CVE-2018-6143", "CVE-2018-6144", "CVE-2018-6145", "CVE-2018-6147");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-21 15:28:00 +0000 (Thu, 21 Dec 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0268)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0268");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0268.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=22138");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/02/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/02/stable-channel-update-for-desktop_22.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/03/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/03/stable-channel-update-for-desktop_13.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/03/stable-channel-update-for-desktop_20.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/04/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/04/stable-channel-update-for-desktop_26.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop_15.html");
  script_xref(name:"URL", value:"https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop_58.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2018-0268 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 67.0.3396.62 fixes security issues:

Multiple flaws were found in the way Chromium 64.0.3282.140 processes various
types of web content, where loading a web page containing malicious content
could cause Chromium to crash, execute arbitrary code, or disclose sensitive
information. (CVE-2017-11215, CVE-2017-11225, CVE-2018-6056, CVE-2018-6057,
CVE-2018-6060, CVE-2018-6061, CVE-2018-6062, CVE-2018-6063, CVE-2018-6064,
CVE-2018-6065, CVE-2018-6066, CVE-2018-6067, CVE-2018-6068, CVE-2018-6069,
CVE-2018-6070, CVE-2018-6071, CVE-2018-6072, CVE-2018-6073, CVE-2018-6074,
CVE-2018-6075, CVE-2018-6076, CVE-2018-6077, CVE-2018-6078, CVE-2018-6079,
CVE-2018-6080, CVE-2018-6081, CVE-2018-6082, CVE-2018-6083, CVE-2018-6084,
CVE-2018-6085, CVE-2018-6086, CVE-2018-6087, CVE-2018-6088, CVE-2018-6089,
CVE-2018-6090, CVE-2018-6091, CVE-2018-6092, CVE-2018-6093, CVE-2018-6094,
CVE-2018-6095, CVE-2018-6096, CVE-2018-6097, CVE-2018-6098, CVE-2018-6099,
CVE-2018-6100, CVE-2018-6101, CVE-2018-6102, CVE-2018-6103, CVE-2018-6104,
CVE-2018-6105, CVE-2018-6106, CVE-2018-6107, CVE-2018-6108, CVE-2018-6109,
CVE-2018-6110, CVE-2018-6111, CVE-2018-6112, CVE-2018-6113, CVE-2018-6114,
CVE-2018-6115, CVE-2018-6116, CVE-2018-6117, CVE-2018-6118, CVE-2018-6120,
CVE-2018-6121, CVE-2018-6122, CVE-2018-6123, CVE-2018-6124, CVE-2018-6126,
CVE-2018-6127, CVE-2018-6128, CVE-2018-6129, CVE-2018-6130, CVE-2018-6131,
CVE-2018-6132, CVE-2018-6133, CVE-2018-6134, CVE-2018-6135, CVE-2018-6136,
CVE-2018-6137, CVE-2018-6138, CVE-2018-6139, CVE-2018-6140, CVE-2018-6141,
CVE-2018-6142, CVE-2018-6143, CVE-2018-6144, CVE-2018-6145, CVE-2018-6147)");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~67.0.3396.62~1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~67.0.3396.62~1.mga6", rls:"MAGEIA6"))) {
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
