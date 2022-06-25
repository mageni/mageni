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
  script_oid("1.3.6.1.4.1.25623.1.0.704562");
  script_version("2019-11-12T03:00:49+0000");
  script_cve_id("CVE-2019-13659", "CVE-2019-13660", "CVE-2019-13661", "CVE-2019-13662", "CVE-2019-13663", "CVE-2019-13664", "CVE-2019-13665", "CVE-2019-13666", "CVE-2019-13667", "CVE-2019-13668", "CVE-2019-13669", "CVE-2019-13670", "CVE-2019-13671", "CVE-2019-13673", "CVE-2019-13674", "CVE-2019-13675", "CVE-2019-13676", "CVE-2019-13677", "CVE-2019-13678", "CVE-2019-13679", "CVE-2019-13680", "CVE-2019-13681", "CVE-2019-13682", "CVE-2019-13683", "CVE-2019-13685", "CVE-2019-13686", "CVE-2019-13687", "CVE-2019-13688", "CVE-2019-13691", "CVE-2019-13692", "CVE-2019-13693", "CVE-2019-13694", "CVE-2019-13695", "CVE-2019-13696", "CVE-2019-13697", "CVE-2019-13699", "CVE-2019-13700", "CVE-2019-13701", "CVE-2019-13702", "CVE-2019-13703", "CVE-2019-13704", "CVE-2019-13705", "CVE-2019-13706", "CVE-2019-13707", "CVE-2019-13708", "CVE-2019-13709", "CVE-2019-13710", "CVE-2019-13711", "CVE-2019-13713", "CVE-2019-13714", "CVE-2019-13715", "CVE-2019-13716", "CVE-2019-13717", "CVE-2019-13718", "CVE-2019-13719", "CVE-2019-13720", "CVE-2019-13721", "CVE-2019-5869", "CVE-2019-5870", "CVE-2019-5871", "CVE-2019-5872", "CVE-2019-5874", "CVE-2019-5875", "CVE-2019-5876", "CVE-2019-5877", "CVE-2019-5878", "CVE-2019-5879", "CVE-2019-5880");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-11-12 03:00:49 +0000 (Tue, 12 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-12 03:00:49 +0000 (Tue, 12 Nov 2019)");
  script_name("Debian Security Advisory DSA 4562-1 (chromium - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4562.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4562-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4562-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2019-5869 
Zhe Jin discovered a use-after-free issue.

CVE-2019-5870 
Guang Gong discovered a use-after-free issue.

CVE-2019-5871 
A buffer overflow issue was discovered in the skia library.

CVE-2019-5872 
Zhe Jin discovered a use-after-free issue.

CVE-2019-5874 
James Lee discovered an issue with external Uniform Resource Identifiers.

CVE-2019-5875 
Khalil Zhani discovered a URL spoofing issue.

CVE-2019-5876 
Man Yue Mo discovered a use-after-free issue.

CVE-2019-5877 
Guang Gong discovered an out-of-bounds read issue.

CVE-2019-5878 
Guang Gong discovered an use-after-free issue in the v8 javascript
library.

CVE-2019-5879 
Jinseo Kim discover that extensions could read files on the local
system.

CVE-2019-5880 
Jun Kokatsu discovered a way to bypass the SameSite cookie feature.

CVE-2019-13659 
Lnyas Zhang discovered a URL spoofing issue.

CVE-2019-13660 
Wenxu Wu discovered a user interface error in full screen mode.

CVE-2019-13661 
Wenxu Wu discovered a user interface spoofing issue in full screen mode.

CVE-2019-13662 
David Erceg discovered a way to bypass the Content Security Policy.

CVE-2019-13663 
Lnyas Zhang discovered a way to spoof Internationalized Domain Names.

CVE-2019-13664 
Thomas Shadwell discovered a way to bypass the SameSite cookie feature.

CVE-2019-13665 
Jun Kokatsu discovered a way to bypass the multiple file download
protection feature.

CVE-2019-13666 
Tom Van Goethem discovered an information leak.

CVE-2019-13667 
Khalil Zhani discovered a URL spoofing issue.

CVE-2019-13668 
David Erceg discovered an information leak.

CVE-2019-13669 
Khalil Zhani discovered an authentication spoofing issue.

CVE-2019-13670 
Guang Gong discovered a memory corruption issue in the v8 javascript
library.

CVE-2019-13671 
xisigr discovered a user interface error.

CVE-2019-13673 
David Erceg discovered an information leak.

CVE-2019-13674 
Khalil Zhani discovered a way to spoof Internationalized Domain Names.

CVE-2019-13675 
Jun Kokatsu discovered a way to disable extensions.

CVE-2019-13676 
Wenxu Wu discovered an error in a certificate warning.

CVE-2019-13677 
Jun Kokatsu discovered an error in the chrome web store.

CVE-2019-13678 
Ronni Skansing discovered a spoofing issue in the download dialog window.

CVE-2019-13679 
Conrad Irwin discovered that user activation was not required for
printing.

CVE-2019-13680 
Thijs Alkamade discovered an IP address spoofing issue.

CVE-2019-13681 
David Erceg discovered a way to bypass download restrictions.

CVE-2019-13682 
Jun Kokatsu discovered a way to bypass the site iso ... 

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), support for chromium has been
discontinued. Please upgrade to the stable release (buster) to continue
receiving chromium updates or switch to firefox, which continues to be
supported in the oldstable release.

For the stable distribution (buster), these problems have been fixed in
version 78.0.3904.97-1~deb10u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"78.0.3904.97-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"78.0.3904.97-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"78.0.3904.97-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"78.0.3904.97-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"78.0.3904.97-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"78.0.3904.97-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);