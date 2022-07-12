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
  script_oid("1.3.6.1.4.1.25623.1.0.704886");
  script_version("2021-04-08T03:00:36+0000");
  script_cve_id("CVE-2021-21159", "CVE-2021-21160", "CVE-2021-21161", "CVE-2021-21162", "CVE-2021-21163", "CVE-2021-21165", "CVE-2021-21166", "CVE-2021-21167", "CVE-2021-21168", "CVE-2021-21169", "CVE-2021-21170", "CVE-2021-21171", "CVE-2021-21172", "CVE-2021-21173", "CVE-2021-21174", "CVE-2021-21175", "CVE-2021-21176", "CVE-2021-21177", "CVE-2021-21178", "CVE-2021-21179", "CVE-2021-21180", "CVE-2021-21181", "CVE-2021-21182", "CVE-2021-21183", "CVE-2021-21184", "CVE-2021-21185", "CVE-2021-21186", "CVE-2021-21187", "CVE-2021-21188", "CVE-2021-21189", "CVE-2021-21190", "CVE-2021-21191", "CVE-2021-21192", "CVE-2021-21193", "CVE-2021-21194", "CVE-2021-21195", "CVE-2021-21196", "CVE-2021-21197", "CVE-2021-21198", "CVE-2021-21199");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-08 03:00:36 +0000 (Thu, 08 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-08 03:00:36 +0000 (Thu, 08 Apr 2021)");
  script_name("Debian: Security Advisory for chromium (DSA-4886-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-4886.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4886-1");
  script_xref(name:"Advisory-ID", value:"DSA-4886-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the DSA-4886-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the chromium web browser.

CVE-2021-21159
Khalil Zhani discovered a buffer overflow issue in the tab implementation.

CVE-2021-21160
Marcin Noga discovered a buffer overflow issue in WebAudio.

CVE-2021-21161
Khalil Zhani discovered a buffer overflow issue in the tab implementation.

CVE-2021-21162
A use-after-free issue was discovered in the WebRTC implementation.

CVE-2021-21163
Alison Huffman discovered a data validation issue.

CVE-2021-21165
Alison Huffman discovered an error in the audio implementation.

CVE-2021-21166
Alison Huffman discovered an error in the audio implementation.

CVE-2021-21167
Leecraso and Guang Gong discovered a use-after-free issue in the bookmarks
implementation.

CVE-2021-21168
Luan Herrera discovered a policy enforcement error in the appcache.

CVE-2021-21169
Bohan Liu and Moon Liang discovered an out-of-bounds access issue in the
v8 javascript library.

CVE-2021-21170
David Erceg discovered a user interface error.

CVE-2021-21171
Irvan Kurniawan discovered a user interface error.

CVE-2021-21172
Maciej Pulikowski discovered a policy enforcement error in the File
System API.

CVE-2021-21173
Tom Van Goethem discovered a network based information leak.

CVE-2021-21174
Ashish Guatam Kambled discovered an implementation error in the Referrer
policy.

CVE-2021-21175
Jun Kokatsu discovered an implementation error in the Site Isolation
feature.

CVE-2021-21176
Luan Herrera discovered an implementation error in the full screen mode.

CVE-2021-21177
Abdulrahman Alqabandi discovered a policy enforcement error in the
Autofill feature.

CVE-2021-21178
Japong discovered an error in the Compositor implementation.

CVE-2021-21179
A use-after-free issue was discovered in the networking implementation.

CVE-2021-21180
Abdulrahman Alqabandi discovered a use-after-free issue in the tab search
feature.

CVE-2021-21181
Xu Lin, Panagiotis Ilias, and Jason Polakis discovered a side-channel
information leak in the Autofill feature.

CVE-2021-21182
Luan Herrera discovered a policy enforcement error in the site navigation
implementation.

CVE-2021-21183
Takashi Yoneuchi discovered an implementation error in the Performance API.

CVE-2021-21184
James Hartig discovered an implementation error in the Performance API.

CVE-2021-21185
David Erceg discovered a policy enforcement error in Extensions.

CVE-2021-21186
dhirajkumarnifty discovered a policy enforcement error in the QR scan
implementation.

CVE-2021-21187
Kirtikumar Anandrao Ramchandani discovered a data validation error in
URL formatting.

CVE-2021-21188
Woojin Oh discovered a  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 89.0.4389.114-1~deb10u1.

We recommend that you upgrade your chromium packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"chromium", ver:"89.0.4389.114-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-common", ver:"89.0.4389.114-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-driver", ver:"89.0.4389.114-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-l10n", ver:"89.0.4389.114-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-sandbox", ver:"89.0.4389.114-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"chromium-shell", ver:"89.0.4389.114-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
