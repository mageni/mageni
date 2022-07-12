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
  script_oid("1.3.6.1.4.1.25623.1.0.704500");
  script_version("2019-08-16T08:19:10+0000");
  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5823", "CVE-2019-5824", "CVE-2019-5825", "CVE-2019-5826", "CVE-2019-5827", "CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840", "CVE-2019-5842", "CVE-2019-5847", "CVE-2019-5848", "CVE-2019-5849", "CVE-2019-5850", "CVE-2019-5851", "CVE-2019-5852", "CVE-2019-5853", "CVE-2019-5854", "CVE-2019-5855", "CVE-2019-5856", "CVE-2019-5857", "CVE-2019-5858", "CVE-2019-5859", "CVE-2019-5860", "CVE-2019-5861", "CVE-2019-5862", "CVE-2019-5864", "CVE-2019-5865", "CVE-2019-5867", "CVE-2019-5868");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-08-16 08:19:10 +0000 (Fri, 16 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 02:01:20 +0000 (Wed, 14 Aug 2019)");
  script_name("Debian Security Advisory DSA 4500-1 (chromium - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4500.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4500-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4500-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-5805
A use-after-free issue was discovered in the pdfium library.

CVE-2019-5806
Wen Xu discovered an integer overflow issue in the Angle library.

CVE-2019-5807
TimGMichaud discovered a memory corruption issue in the v8 javascript
library.

CVE-2019-5808
cloudfuzzer discovered a use-after-free issue in Blink/Webkit.

CVE-2019-5809
Mark Brand discovered a use-after-free issue in Blink/Webkit.

CVE-2019-5810
Mark Amery discovered an information disclosure issue.

CVE-2019-5811
Jun Kokatsu discovered a way to bypass the Cross-Origin Resource Sharing
feature.

CVE-2019-5813
Aleksandar Nikolic discovered an out-of-bounds read issue in the v8
javascript library.

CVE-2019-5814
@AaylaSecura1138 discovered a way to bypass the Cross-Origin Resource
Sharing feature.

CVE-2019-5815
Nicolas Grégoire discovered a buffer overflow issue in Blink/Webkit.

CVE-2019-5818
Adrian Tolbaru discovered an uninitialized value issue.

CVE-2019-5819
Svyat Mitin discovered an error in the developer tools.

CVE-2019-5820
pdknsk discovered an integer overflow issue in the pdfium library.

CVE-2019-5821
pdknsk discovered another integer overflow issue in the pdfium library.

CVE-2019-5822
Jun Kokatsu discovered a way to bypass the Cross-Origin Resource Sharing
feature.

CVE-2019-5823
David Erceg discovered a navigation error.

CVE-2019-5824
leecraso and Guang Gong discovered an error in the media player.

CVE-2019-5825
Genming Liu, Jianyu Chen, Zhen Feng, and Jessica Liu discovered an
out-of-bounds write issue in the v8 javascript library.

CVE-2019-5826
Genming Liu, Jianyu Chen, Zhen Feng, and Jessica Liu discovered a
use-after-free issue.

CVE-2019-5827
mlfbrown discovered an out-of-bounds read issue in the sqlite library.

CVE-2019-5828
leecraso and Guang Gong discovered a use-after-free issue.

CVE-2019-5829
Lucas Pinheiro discovered a use-after-free issue.

CVE-2019-5830
Andrew Krashichkov discovered a credential error in the Cross-Origin
Resource Sharing feature.

CVE-2019-5831
yngwei discovered a map error in the v8 javascript library.

CVE-2019-5832
Sergey Shekyan discovered an error in the Cross-Origin Resource Sharing
feature.

CVE-2019-5833
Khalil Zhani discovered a user interface error.

CVE-2019-5834
Khalil Zhani discovered a URL spoofing issue.

CVE-2019-5836
Omair discovered a buffer overflow issue in the Angle library.

CVE-2019-5837
Adam Iawniuk discovered an information disclosure issue.

CVE-2019-5838
David Erceg discovered an error in extension permissions.

CVE-2019-5839
Masato Kinugawa discovered implementat ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 76.0.3809.100-1~deb10u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"76.0.3809.100-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"76.0.3809.100-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"76.0.3809.100-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"76.0.3809.100-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"76.0.3809.100-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"76.0.3809.100-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);