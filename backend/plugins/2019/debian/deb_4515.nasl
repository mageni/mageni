# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704515");
  script_version("2019-09-06T02:00:20+0000");
  script_cve_id("CVE-2019-8644", "CVE-2019-8649", "CVE-2019-8658", "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8690");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-09-06 02:00:20 +0000 (Fri, 06 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-06 02:00:20 +0000 (Fri, 06 Sep 2019)");
  script_name("Debian Security Advisory DSA 4515-1 (webkit2gtk - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4515.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4515-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk'
  package(s) announced via the DSA-4515-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the webkit2gtk web
engine:

CVE-2019-8644
G. Geshev discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8649
Sergei Glazunov discovered an issue that may lead to universal
cross site scripting.

CVE-2019-8658
akayn discovered an issue that may lead to universal cross site
scripting.

CVE-2019-8666
Zongming Wang and Zhe Jin discovered memory corruption issues that
can lead to arbitrary code execution.

CVE-2019-8669
akayn discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8671
Apple discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8672
Samuel Gross discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8673
Soyeon Park and Wen Xu discovered memory corruption issues that
can lead to arbitrary code execution.

CVE-2019-8676
Soyeon Park and Wen Xu discovered memory corruption issues that
can lead to arbitrary code execution.

CVE-2019-8677
Jihui Lu discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8678
An anonymous researcher, Anthony Lai, Ken Wong, Jeonghoon Shin,
Johnny Yu, Chris Chan, Phil Mok, Alan Ho, and Byron Wai discovered
memory corruption issues that can lead to arbitrary code
execution.

CVE-2019-8679
Jihui Lu discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8680
Jihui Lu discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8681
G. Geshev discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8683
lokihardt discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8684
lokihardt discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8686
G. Geshev discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8687
Apple discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8688
Insu Yun discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8689
lokihardt discovered memory corruption issues that can lead to
arbitrary code execution.

CVE-2019-8690
Sergei Glazunov discovered an issue that may lead to universal
cross site scripting.

You can see more details on the WebKitGTK and WPE WebKit Security
Advisory WSA-2019-0004.");

  script_tag(name:"affected", value:"'webkit2gtk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2.24.4-1~deb10u1.

We recommend that you upgrade your webkit2gtk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-javascriptcoregtk-4.0", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"gir1.2-webkit2-4.0", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-18", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-bin", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjavascriptcoregtk-4.0-dev", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-37-gtk2", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-dev", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libwebkit2gtk-4.0-doc", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"webkit2gtk-driver", ver:"2.24.4-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);