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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0274");
  script_cve_id("CVE-2016-1705", "CVE-2016-1706", "CVE-2016-1708", "CVE-2016-1709", "CVE-2016-1710", "CVE-2016-1711", "CVE-2016-5127", "CVE-2016-5128", "CVE-2016-5129", "CVE-2016-5130", "CVE-2016-5133", "CVE-2016-5134", "CVE-2016-5135", "CVE-2016-5136", "CVE-2016-5137");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-01 01:29:00 +0000 (Fri, 01 Sep 2017)");

  script_name("Mageia: Security Advisory (MGASA-2016-0274)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0274");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0274.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19007");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2016/07/stable-channel-update.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0274 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple unspecified vulnerabilities in chromium before 52.0.2743.82 allow
attackers to cause a denial of service or possibly have other impact via
unknown vectors. (CVE-2016-1705)

The PPAPI implementation in Chromium before 52.0.2743.82 does not validate
the origin of IPC messages to the plugin broker process that should have
come from the browser process, which allows remote attackers to bypass a
sandbox protection mechanism via an unexpected message type, related to
broker_process_dispatcher.cc, ppapi_plugin_process_host.cc,
ppapi_thread.cc, and render_frame_message_filter.cc. (CVE-2016-1706)

The Chrome Web Store inline-installation implementation in the Extensions
subsystem in Chromium before 52.0.2743.82 does not properly consider
object lifetimes during progress observation, which allows remote
attackers to cause a denial of service (use-after-free) or possibly have
unspecified other impact via a crafted web site. (CVE-2016-1708)

Heap-based buffer overflow in the ByteArray::Get method in
data/byte_array.cc in sfntly before 2016-06-10, as used in Chromium before
52.0.2743.82, allows remote attackers to cause a denial of service or
possibly have unspecified other impact via a crafted SFNT font.
(CVE-2016-1709)

The ChromeClientImpl::createWindow method in
WebKit/Source/web/ChromeClientImpl.cpp in Blink, as used in Chromium
before 52.0.2743.82, does not prevent window creation by a deferred frame,
which allows remote attackers to bypass the Same Origin Policy via a
crafted web site. (CVE-2016-1710)

WebKit/Source/core/loader/FrameLoader.cpp in Blink, as used in Chromium
before 52.0.2743.82, does not disable frame navigation during a detach
operation on a DocumentLoader object, which allows remote attackers to
bypass the Same Origin Policy via a crafted web site. (CVE-2016-1711)

Use-after-free vulnerability in
WebKit/Source/core/editing/VisibleUnits.cpp in Blink, as used in Chromium
before 52.0.2743.82, allows remote attackers to cause a denial of service
or possibly have unspecified other impact via crafted JavaScript code
involving an @import at-rule in a Cascading Style Sheets (CSS) token
sequence in conjunction with a rel=import attribute of a LINK element.
(CVE-2016-5127)

objects.cc in V8 before 5.2.361.27, as used in Chromium before
52.0.2743.82, does not prevent API interceptors from modifying a store
target without setting a property, which allows remote attackers to bypass
the Same Origin Policy via a crafted web site. (CVE-2016-5128)

V8 before 5.2.361.32, as used in Chromium before 52.0.2743.82, does not
properly process left-trimmed objects, which allows remote attackers to
cause a denial of service (memory corruption) or possibly have unspecified
other impact via crafted JavaScript code. (CVE-2016-5129)

content/renderer/history_controller.cc in Chromium before 52.0.2743.82
does not properly restrict multiple uses of a JavaScript forward method,
which ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'chromium-browser-stable' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~52.0.2743.82~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~52.0.2743.82~1.mga5", rls:"MAGEIA5"))) {
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
