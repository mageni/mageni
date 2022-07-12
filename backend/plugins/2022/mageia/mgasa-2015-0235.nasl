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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0235");
  script_cve_id("CVE-2015-1251", "CVE-2015-1252", "CVE-2015-1253", "CVE-2015-1254", "CVE-2015-1255", "CVE-2015-1256", "CVE-2015-1257", "CVE-2015-1258", "CVE-2015-1259", "CVE-2015-1260", "CVE-2015-1262", "CVE-2015-1263", "CVE-2015-1264", "CVE-2015-1265");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 02:59:00 +0000 (Tue, 03 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0235");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0235.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15993");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/05/stable-channel-update_19.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium-browser 43.0.2357.65 fixes a number of security issues:

Use-after-free vulnerability in the SpeechRecognitionClient implementation
in the Speech subsystem in Google Chrome before 43.0.2357.65 allows remote
attackers to execute arbitrary code via a crafted document. (CVE-2015-1251)

common/partial_circular_buffer.cc in Google Chrome before 43.0.2357.65 does
not properly handle wraps, which allows remote attackers to bypass a
sandbox protection mechanism or cause a denial of service (out-of-bounds
write) via vectors that trigger a write operation with a large amount of
data, related to the PartialCircularBuffer::Write and
PartialCircularBuffer::DoWrite functions. (CVE-2015-1252)

core/html/parser/HTMLConstructionSite.cpp in the DOM implementation in
Blink, as used in Google Chrome before 43.0.2357.65, allows remote
attackers to bypass the Same Origin Policy via crafted JavaScript code that
appends a child to a SCRIPT element, related to the insert and
executeReparentTask functions. (CVE-2015-1253)

core/dom/Document.cpp in Blink, as used in Google Chrome before
43.0.2357.65, enables the inheritance of the designMode attribute, which
allows remote attackers to bypass the Same Origin Policy by leveraging the
availability of editing. (CVE-2015-1254)

Use-after-free vulnerability in
content/renderer/media/webaudio_capturer_source.cc in the WebAudio
implementation in Google Chrome before 43.0.2357.65 allows remote attackers
to cause a denial of service (heap memory corruption) or possibly have
unspecified other impact by leveraging improper handling of a stop action
for an audio track. (CVE-2015-1255)

Use-after-free vulnerability in the SVG implementation in Blink, as used in
Google Chrome before 43.0.2357.65, allows remote attackers to cause a
denial of service or possibly have unspecified other impact via a crafted
document that leverages improper handling of a shadow tree for a use
element. (CVE-2015-1256)

platform/graphics/filters/FEColorMatrix.cpp in the SVG implementation in
Blink, as used in Google Chrome before 43.0.2357.65, does not properly
handle an insufficient number of values in an feColorMatrix filter, which
allows remote attackers to cause a denial of service (container overflow)
or possibly have unspecified other impact via a crafted document.
(CVE-2015-1257)

Google Chrome before 43.0.2357.65 relies on libvpx code that was not built
with an appropriate --size-limit value, which allows remote attackers to
trigger a negative value for a size field, and consequently cause a denial
of service or possibly have unspecified other impact, via a crafted frame
size in VP9 video data. (CVE-2015-1258)

PDFium, as used in Google Chrome before 43.0.2357.65, does not properly
initialize memory, which allows remote attackers to cause a denial of
service or possibly have unspecified other impact via unknown vectors.
(CVE-2015-1259)

Multiple use-after-free ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~43.0.2357.65~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~43.0.2357.65~1.mga4", rls:"MAGEIA4"))) {
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
