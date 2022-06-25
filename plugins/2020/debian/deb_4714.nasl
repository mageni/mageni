# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.704714");
  script_version("2020-07-03T03:01:04+0000");
  script_cve_id("CVE-2020-6423", "CVE-2020-6430", "CVE-2020-6431", "CVE-2020-6432", "CVE-2020-6433", "CVE-2020-6434", "CVE-2020-6435", "CVE-2020-6436", "CVE-2020-6437", "CVE-2020-6438", "CVE-2020-6439", "CVE-2020-6440", "CVE-2020-6441", "CVE-2020-6442", "CVE-2020-6443", "CVE-2020-6444", "CVE-2020-6445", "CVE-2020-6446", "CVE-2020-6447", "CVE-2020-6448", "CVE-2020-6454", "CVE-2020-6455", "CVE-2020-6456", "CVE-2020-6457", "CVE-2020-6458", "CVE-2020-6459", "CVE-2020-6460", "CVE-2020-6461", "CVE-2020-6462", "CVE-2020-6463", "CVE-2020-6464", "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491", "CVE-2020-6493", "CVE-2020-6494", "CVE-2020-6495", "CVE-2020-6496", "CVE-2020-6497", "CVE-2020-6498", "CVE-2020-6505", "CVE-2020-6506", "CVE-2020-6507", "CVE-2020-6509", "CVE-2020-6831");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-03 10:14:24 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-03 03:01:04 +0000 (Fri, 03 Jul 2020)");
  script_name("Debian: Security Advisory for chromium (DSA-4714-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4714.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4714-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4714-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2020-6423
A use-after-free issue was found in the audio implementation.

CVE-2020-6430
Avihay Cohen discovered a type confusion issue in the v8 javascript
library.

CVE-2020-6431
Luan Herrera discovered a policy enforcement error.

CVE-2020-6432
Luan Herrera discovered a policy enforcement error.

CVE-2020-6433
Luan Herrera discovered a policy enforcement error in extensions.

CVE-2020-6434
HyungSeok Han discovered a use-after-free issue in the developer tools.

CVE-2020-6435
Sergei Glazunov discovered a policy enforcement error in extensions.

CVE-2020-6436
Igor Bukanov discovered a use-after-free issue.

CVE-2020-6437
Jann Horn discovered an implementation error in WebView.

CVE-2020-6438
Ng Yik Phang discovered a policy enforcement error in extensions.

CVE-2020-6439
remkoboonstra discovered a policy enforcement error.

CVE-2020-6440
David Erceg discovered an implementation error in extensions.

CVE-2020-6441
David Erceg discovered a policy enforcement error.

CVE-2020-6442
B@rMey discovered an implementation error in the page cache.

CVE-2020-6443
@lovasoa discovered an implementation error in the developer tools.

CVE-2020-6444
mlfbrown discovered an uninitialized variable in the WebRTC
implementation.

CVE-2020-6445
Jun Kokatsu discovered a policy enforcement error.

CVE-2020-6446
Jun Kokatsu discovered a policy enforcement error.

CVE-2020-6447
David Erceg discovered an implementation error in the developer tools.

CVE-2020-6448
Guang Gong discovered a use-after-free issue in the v8 javascript library.

CVE-2020-6454
Leecraso and Guang Gong discovered a use-after-free issue in extensions.

CVE-2020-6455
Nan Wang and Guang Gong discovered an out-of-bounds read issue in the
WebSQL implementation.

CVE-2020-6456
Micha? Bentkowski discovered insufficient validation of untrusted input.

CVE-2020-6457
Leecraso and Guang Gong discovered a use-after-free issue in the speech
recognizer.

CVE-2020-6458
Aleksandar Nikolic discoved an out-of-bounds read and write issue in the
pdfium library.

CVE-2020-6459
Zhe Jin discovered a use-after-free issue in the payments implementation.

CVE-2020-6460
It was discovered that URL formatting was insufficiently validated.

CVE-2020-6461
Zhe Jin discovered a use-after-free issue.

CVE-2020-6462
Zhe Jin discovered a use-after-free issue in task scheduling.

CVE-2020-6463
Pawel Wylecial discovered a use-after-free issue in the ANGLE library.

CVE-2020-6464
Looben Yang discovered a type confusion issue in Blink/Webkit.

CVE-2020-6465
Woojin Oh discovered a use-after-free iss ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), security support for chromium
has been discontinued.

For the stable distribution (buster), these problems have been fixed in
version 83.0.4103.116-1~deb10u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"83.0.4103.116-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
