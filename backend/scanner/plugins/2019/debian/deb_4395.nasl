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
  script_oid("1.3.6.1.4.1.25623.1.0.704395");
  script_version("$Revision: 14285 $");
  script_cve_id("CVE-2018-17481", "CVE-2019-5754", "CVE-2019-5755", "CVE-2019-5756", "CVE-2019-5757",
                "CVE-2019-5758", "CVE-2019-5759", "CVE-2019-5760", "CVE-2019-5762", "CVE-2019-5763",
                "CVE-2019-5764", "CVE-2019-5765", "CVE-2019-5766", "CVE-2019-5767", "CVE-2019-5768",
                "CVE-2019-5769", "CVE-2019-5770", "CVE-2019-5772", "CVE-2019-5773", "CVE-2019-5774",
                "CVE-2019-5775", "CVE-2019-5776", "CVE-2019-5777", "CVE-2019-5778", "CVE-2019-5779",
                "CVE-2019-5780", "CVE-2019-5781", "CVE-2019-5782", "CVE-2019-5783", "CVE-2019-5784");
  script_name("Debian Security Advisory DSA 4395-1 (chromium - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 16:08:34 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-18 00:00:00 +0100 (Mon, 18 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4395.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");
  script_tag(name:"affected", value:"chromium on Debian Linux");
  script_tag(name:"solution", value:"For the stable distribution (stretch), these problems have been fixed in
version 72.0.3626.96-1~deb9u1.

We recommend that you upgrade your chromium packages.

For the detailed security status of chromium please refer to
its security tracker page linked in the references.");

  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/chromium");
  script_tag(name:"summary", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2018-17481
A use-after-free issue was discovered in the pdfium library.

CVE-2019-5754
Klzgrad discovered an error in the QUIC networking implementation.

CVE-2019-5755
Jay Bosamiya discovered an implementation error in the v8 javascript
library.

CVE-2019-5756
A use-after-free issue was discovered in the pdfium library.

CVE-2019-5757
Alexandru Pitis discovered a type confusion error in the SVG image
format implementation.

CVE-2019-5758
Zhe Jin discovered a use-after-free issue in blink/webkit.

CVE-2019-5759
Almog Benin discovered a use-after-free issue when handling HTML pages
containing select elements.

CVE-2019-5760
Zhe Jin discovered a use-after-free issue in the WebRTC implementation.

CVE-2019-5762
A use-after-free issue was discovered in the pdfium library.

CVE-2019-5763
Guang Gon discovered an input validation error in the v8 javascript
library.

CVE-2019-5764
Eyal Itkin discovered a use-after-free issue in the WebRTC implementation.

CVE-2019-5765
Sergey Toshin discovered a policy enforcement error.

CVE-2019-5766
David Erceg discovered a policy enforcement error.

CVE-2019-5767
Haoran Lu, Yifan Zhang, Luyi Xing, and Xiaojing Liao reported an error
in the WebAPKs user interface.

CVE-2019-5768
Rob Wu discovered a policy enforcement error in the developer tools.

CVE-2019-5769
Guy Eshel discovered an input validation error in blink/webkit.

CVE-2019-5770
hemidallt discovered a buffer overflow issue in the WebGL implementation.

CVE-2019-5772
Zhen Zhou discovered a use-after-free issue in the pdfium library.

CVE-2019-5773
Yongke Wong discovered an input validation error in the IndexDB
implementation.

CVE-2019-5774
Junghwan Kang and Juno Im discovered an input validation error in the
SafeBrowsing implementation.

CVE-2019-5775
evil1m0 discovered a policy enforcement error.

CVE-2019-5776
Lnyas Zhang discovered a policy enforcement error.

CVE-2019-5777
Khalil Zhani discovered a policy enforcement error.

CVE-2019-5778
David Erceg discovered a policy enforcement error in the Extensions
implementation.

CVE-2019-5779
David Erceg discovered a policy enforcement error in the ServiceWorker
implementation.

CVE-2019-5780
Andreas Hegenberg discovered a policy enforcement error.

CVE-2019-5781
evil1m0 discovered a policy enforcement error.

CVE-2019-5782
Qixun Zhao discovered an implementation error in the v8 javascript library.

CVE-2019-5783
Shintaro Kobori discovered an input validation error in the developer
tools.

CVE-2019-5784
Lucas Pinheiro discovered an implementation error in the v8 javascript
library.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"chromedriver", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-driver", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-l10n", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-shell", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"chromium-widevine", ver:"72.0.3626.96-1~deb9u1", rls:"DEB9")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}