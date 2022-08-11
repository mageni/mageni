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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0123");
  script_cve_id("CVE-2015-1213", "CVE-2015-1214", "CVE-2015-1215", "CVE-2015-1216", "CVE-2015-1217", "CVE-2015-1218", "CVE-2015-1219", "CVE-2015-1220", "CVE-2015-1221", "CVE-2015-1222", "CVE-2015-1223", "CVE-2015-1224", "CVE-2015-1225", "CVE-2015-1226", "CVE-2015-1227", "CVE-2015-1228", "CVE-2015-1229", "CVE-2015-1231", "CVE-2015-1232");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-22 02:59:00 +0000 (Thu, 22 Dec 2016)");

  script_name("Mageia: Security Advisory (MGASA-2015-0123)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0123");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0123.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15433");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/02/stable-channel-update_19.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/03/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/03/stable-channel-update_10.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/03/stable-channel-update_19.html");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/201503-12");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0123 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser packages fix security vulnerabilities:

The SkBitmap::ReadRawPixels function in core/SkBitmap.cpp in the filters
implementation in Skia, as used in Google Chrome before 41.0.2272.76, allows
remote attackers to cause a denial of service or possibly have unspecified
other impact via vectors that trigger an out-of-bounds write operation
(CVE-2015-1213).

Integer overflow in the SkAutoSTArray implementation in
include/core/SkTemplates.h in the filters implementation in Skia, as used in
Google Chrome before 41.0.2272.76, allows remote attackers to cause a denial
of service or possibly have unspecified other impact via vectors that trigger
a reset action with a large count value, leading to an out-of-bounds write
operation (CVE-2015-1214).

The filters implementation in Skia, as used in Google Chrome before
41.0.2272.76, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via vectors that trigger an
out-of-bounds write operation (CVE-2015-1215).

Use-after-free vulnerability in the V8Window::namedPropertyGetterCustom
function in bindings/core/v8/custom/V8WindowCustom.cpp in the V8 bindings in
Blink, as used in Google Chrome before 41.0.2272.76, allows remote attackers
to cause a denial of service or possibly have unspecified other impact via
vectors that trigger a frame detachment (CVE-2015-1216).

The V8LazyEventListener::prepareListenerObject function in
bindings/core/v8/V8LazyEventListener.cpp in the V8 bindings in Blink, as used
in Google Chrome before 41.0.2272.76, does not properly compile listeners,
which allows remote attackers to cause a denial of service or possibly have
unspecified other impact via vectors that leverage 'type confusion'
(CVE-2015-1217).

Multiple use-after-free vulnerabilities in the DOM implementation in Blink,
as used in Google Chrome before 41.0.2272.76, allow remote attackers to cause
a denial of service or possibly have unspecified other impact via vectors
that trigger movement of a SCRIPT element to different documents, related to
the HTMLScriptElement::didMoveToNewDocument function in
core/html/HTMLScriptElement.cpp and the
SVGScriptElement::didMoveToNewDocument function in
core/svg/SVGScriptElement.cpp (CVE-2015-1218).

Integer overflow in the SkMallocPixelRef::NewAllocate function in
core/SkMallocPixelRef.cpp in Skia, as used in Google Chrome before
41.0.2272.76, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via vectors that trigger an attempted
allocation of a large amount of memory during WebGL rendering
(CVE-2015-1219).

Use-after-free vulnerability in the GIFImageReader::parseData function in
platform/image-decoders/gif/GIFImageReader.cpp in Blink, as used in Google
Chrome before 41.0.2272.76, allows remote attackers to cause a denial of
service or possibly have unspecified other impact via a crafted frame size in
a GIF ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~41.0.2272.101~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~41.0.2272.101~1.mga4", rls:"MAGEIA4"))) {
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
