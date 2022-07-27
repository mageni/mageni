# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.2.2021.1347");
  script_version("2021-02-22T08:40:04+0000");
  script_cve_id("CVE-2017-14927", "CVE-2017-9865", "CVE-2018-21009", "CVE-2019-12293", "CVE-2019-12360", "CVE-2019-9631");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-02-23 12:20:55 +0000 (Tue, 23 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-22 08:40:04 +0000 (Mon, 22 Feb 2021)");
  script_name("Huawei EulerOS: Security Advisory for poppler (EulerOS-SA-2021-1347)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS-2\.0SP2");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2021-1347");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1347");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS
  'poppler' package(s) announced via the EulerOS-SA-2021-1347 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Poppler 0.74.0 has a heap-based buffer over-read in the CairoRescaleBox.cc downsample_row_box_filter function.(CVE-2019-9631)

In Poppler through 0.76.1, there is a heap-based buffer over-read in JPXStream::init in JPEG2000Stream.cc via data with inconsistent heights or widths.(CVE-2019-12293)

A stack-based buffer over-read exists in FoFiTrueType::dumpString in fofi/FoFiTrueType.cc in Xpdf 4.01.01. It can, for example, be triggered by sending crafted TrueType data in a PDF document to the pdftops tool. It might allow an attacker to cause Denial of Service or leak memory data into dump content.(CVE-2019-12360)

Poppler before 0.66.0 has an integer overflow in Parser::makeStream in Parser.cc.(CVE-2018-21009)

In Poppler 0.59.0, a NULL Pointer Dereference exists in the SplashOutputDev::type3D0() function in SplashOutputDev.cc via a crafted PDF document.(CVE-2017-14927)

The function GfxImageColorMap::getGray in GfxState.cc in Poppler 0.54.0 allows remote attackers to cause a denial of service (stack-based buffer over-read and application crash) via a crafted PDF document, related to missing color-map validation in ImageOutputDev.cc.(CVE-2017-9865)");

  script_tag(name:"affected", value:"'poppler' package(s) on Huawei EulerOS V2.0SP2.");

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

if(release == "EULEROS-2.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.26.5~17.h23", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-glib", rpm:"poppler-glib~0.26.5~17.h23", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-qt", rpm:"poppler-qt~0.26.5~17.h23", rls:"EULEROS-2.0SP2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.26.5~17.h23", rls:"EULEROS-2.0SP2"))) {
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