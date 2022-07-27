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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0011");
  script_cve_id("CVE-2016-5407", "CVE-2016-7942", "CVE-2016-7943", "CVE-2016-7944", "CVE-2016-7945", "CVE-2016-7946", "CVE-2016-7947", "CVE-2016-7948", "CVE-2016-7949", "CVE-2016-7950", "CVE-2016-7951", "CVE-2016-7952", "CVE-2016-7953");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0011)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0011");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0011.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19530");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2016/10/04/4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libx11, libxfixes, libxi, libxrandr, libxrender, libxtst, libxv, libxvmc' package(s) announced via the MGASA-2018-0011 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The XvQueryAdaptors and XvQueryEncodings functions in X.org libXv before
1.0.11 allow remote X servers to trigger out-of-bounds memory access
operations via vectors involving length specifications in received data
(CVE-2016-5407).

The XGetImage function in X.org libX11 before 1.6.4 might allow remote X
servers to gain privileges via vectors involving image type and geometry,
which triggers out-of-bounds read operations (CVE-2016-7942).

The XListFonts function in X.org libX11 before 1.6.4 might allow remote X
servers to gain privileges via vectors involving length fields, which
trigger out-of-bounds write operations (CVE-2016-7943).

Integer overflow in X.org libXfixes before 5.0.3 on 32-bit platforms might
allow remote X servers to gain privileges via a length value of INT_MAX,
which triggers the client to stop reading data and get out of sync
(CVE-2016-7944).

Multiple integer overflows in X.org libXi before 1.7.7 allow remote X
servers to cause a denial of service (out-of-bounds memory access or
infinite loop) via vectors involving length fields (CVE-2016-7945).

X.org libXi before 1.7.7 allows remote X servers to cause a denial of
service (infinite loop) via vectors involving length fields
(CVE-2016-7946).

Multiple integer overflows in X.org libXrandr before 1.5.1 allow remote X
servers to trigger out-of-bounds write operations via a crafted response
(CVE-2016-7947).

X.org libXrandr before 1.5.1 allows remote X servers to trigger
out-of-bounds write operations by leveraging mishandling of reply data
(CVE-2016-7948).

Multiple buffer overflows in the XvQueryAdaptors and XvQueryEncodings
functions in X.org libXrender before 0.9.10 allow remote X servers to
trigger out-of-bounds write operations via vectors involving length fields
(CVE-2016-7949).

The XRenderQueryFilters function in X.org libXrender before 0.9.10 allows
remote X servers to trigger out-of-bounds write operations via vectors
involving filter name lengths (CVE-2016-7950).

Multiple integer overflows in X.org libXtst before 1.2.3 allow remote X
servers to trigger out-of-bounds memory access operations by leveraging
the lack of range checks (CVE-2016-7951).

X.org libXtst before 1.2.3 allows remote X servers to cause a denial of
service (infinite loop) via a reply in the XRecordStartOfData,
XRecordEndOfData, or XRecordClientDied category without a client sequence
and with attached data (CVE-2016-7952).

Buffer underflow in X.org libXvMC before 1.0.10 allows remote X servers to
have unspecified impact via an empty string (CVE-2016-7953).");

  script_tag(name:"affected", value:"'libx11, libxfixes, libxi, libxrandr, libxrender, libxtst, libxv, libxvmc' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-devel", rpm:"lib64x11-devel~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11-xcb1", rpm:"lib64x11-xcb1~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64x11_6", rpm:"lib64x11_6~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfixes-devel", rpm:"lib64xfixes-devel~5.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xfixes3", rpm:"lib64xfixes3~5.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xi-devel", rpm:"lib64xi-devel~1.7.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xi6", rpm:"lib64xi6~1.7.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrandr-devel", rpm:"lib64xrandr-devel~1.4.2~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrandr2", rpm:"lib64xrandr2~1.4.2~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrender-devel", rpm:"lib64xrender-devel~0.9.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xrender1", rpm:"lib64xrender1~0.9.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xtst-devel", rpm:"lib64xtst-devel~1.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xtst6", rpm:"lib64xtst6~1.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xv-devel", rpm:"lib64xv-devel~1.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xv1", rpm:"lib64xv1~1.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xvmc-devel", rpm:"lib64xvmc-devel~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64xvmc1", rpm:"lib64xvmc1~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11", rpm:"libx11~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-common", rpm:"libx11-common~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-devel", rpm:"libx11-devel~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-doc", rpm:"libx11-doc~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11-xcb1", rpm:"libx11-xcb1~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libx11_6", rpm:"libx11_6~1.6.5~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes", rpm:"libxfixes~5.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes-devel", rpm:"libxfixes-devel~5.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxfixes3", rpm:"libxfixes3~5.0.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi", rpm:"libxi~1.7.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi-devel", rpm:"libxi-devel~1.7.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxi6", rpm:"libxi6~1.7.7~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr", rpm:"libxrandr~1.4.2~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr-devel", rpm:"libxrandr-devel~1.4.2~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrandr2", rpm:"libxrandr2~1.4.2~4.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender", rpm:"libxrender~0.9.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender-devel", rpm:"libxrender-devel~0.9.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxrender1", rpm:"libxrender1~0.9.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst", rpm:"libxtst~1.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst-devel", rpm:"libxtst-devel~1.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxtst6", rpm:"libxtst6~1.2.3~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv", rpm:"libxv~1.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv-devel", rpm:"libxv-devel~1.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxv1", rpm:"libxv1~1.0.11~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc", rpm:"libxvmc~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc-devel", rpm:"libxvmc-devel~1.0.10~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxvmc1", rpm:"libxvmc1~1.0.10~1.mga5", rls:"MAGEIA5"))) {
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
