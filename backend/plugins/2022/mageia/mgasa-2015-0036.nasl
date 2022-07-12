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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0036");
  script_cve_id("CVE-2014-7924", "CVE-2014-7925", "CVE-2014-7927", "CVE-2014-7928", "CVE-2014-7929", "CVE-2014-7930", "CVE-2014-7931", "CVE-2014-7932", "CVE-2014-7934", "CVE-2014-7935", "CVE-2014-7936", "CVE-2014-7938", "CVE-2014-7939", "CVE-2014-7941", "CVE-2014-7942", "CVE-2014-7943", "CVE-2014-7946", "CVE-2014-7948", "CVE-2015-1205");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-03 02:59:00 +0000 (Tue, 03 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0036)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0036");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0036.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15105");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/11/stable-channel-update_25.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2014/12/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/01/stable-channel-update.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/01/stable-update.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0036 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser packages fix security vulnerabilities:

Use-after-free vulnerability in the IndexedDB implementation in Google Chrome
before 40.0.2214.91 allows remote attackers to cause a denial of service or
possibly have unspecified other impact by triggering duplicate BLOB
references, related to content/browser/indexed_db/indexed_db_callbacks.cc and
content/browser/indexed_db/indexed_db_dispatcher_host.cc (CVE-2014-7924).

Use-after-free vulnerability in the WebAudio implementation in Blink, as used
in Google Chrome before 40.0.2214.91, allows remote attackers to cause a
denial of service or possibly have unspecified other impact via vectors that
trigger an audio-rendering thread in which AudioNode data is improperly
maintained (CVE-2014-7925).

The SimplifiedLowering::DoLoadBuffer function in
compiler/simplified-lowering.cc in Google V8, as used in Google Chrome before
40.0.2214.91, does not properly choose an integer data type, which allows
remote attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via crafted JavaScript code (CVE-2014-7927).

hydrogen.cc in Google V8, as used Google Chrome before 40.0.2214.91, does not
properly handle arrays with holes, which allows remote attackers to cause a
denial of service (memory corruption) or possibly have unspecified other
impact via crafted JavaScript code that triggers an array copy
(CVE-2014-7928).

Use-after-free vulnerability in core/events/TreeScopeEventContext.cpp in the
DOM implementation in Blink, as used in Google Chrome before 40.0.2214.91,
allows remote attackers to cause a denial of service or possibly have
unspecified other impact via crafted JavaScript code that triggers improper
maintenance of TreeScope data (CVE-2014-7930).

factory.cc in Google V8, as used in Google Chrome before 40.0.2214.91, allows
remote attackers to cause a denial of service (memory corruption) or possibly
have unspecified other impact via crafted JavaScript code that triggers
improper maintenance of backing-store pointers (CVE-2014-7931).

Use-after-free vulnerability in the HTMLScriptElement::didMoveToNewDocument
function in core/html/HTMLScriptElement.cpp in the DOM implementation in
Blink, as used in Google Chrome before 40.0.2214.91, allows remote attackers
to cause a denial of service or possibly have unspecified other impact via
vectors involving movement of a SCRIPT element across documents
(CVE-2014-7929).

Use-after-free vulnerability in the Element::detach function in
core/dom/Element.cpp in the DOM implementation in Blink, as used in Google
Chrome before 40.0.2214.91, allows remote attackers to cause a denial of
service or possibly have unspecified other impact via vectors involving
pending updates of detached elements (CVE-2014-7932).

Use-after-free vulnerability in the DOM implementation in Blink, as used in
Google Chrome before 40.0.2214.91, allows remote ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~40.0.2214.91~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~40.0.2214.91~1.mga4", rls:"MAGEIA4"))) {
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
