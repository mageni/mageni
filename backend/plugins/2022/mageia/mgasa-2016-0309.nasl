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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0309");
  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167", "CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173", "CVE-2016-5174", "CVE-2016-5175");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)");

  script_name("Mageia: Security Advisory (MGASA-2016-0309)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0309");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0309.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=19281");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/08/stable-channel-update-for-desktop_31.html");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/09/stable-channel-update-for-desktop.html");
  script_xref(name:"URL", value:"https://googlechromereleases.blogspot.com/2016/09/stable-channel-update-for-desktop_13.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2016-0309 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Blink, as used in Chromium before 53.0.2785.89 on Windows and OS X and
before 53.0.2785.92 on Linux, mishandles deferred page loads, which
allows remote attackers to inject arbitrary web script or HTML via a
crafted web site, aka 'Universal XSS (UXSS).' (CVE-2016-5147)

Cross-site scripting (XSS) vulnerability in Blink, as used in Chromium
before 53.0.2785.89 on Windows and OS X and before 53.0.2785.92 on
Linux, allows remote attackers to inject arbitrary web script or HTML
via vectors related to widget updates, aka 'Universal XSS (UXSS).'
(CVE-2016-5148)

The extensions subsystem in Chromium before 53.0.2785.89 on Windows and
OS X and before 53.0.2785.92 on Linux relies on an IFRAME source URL to
identify an associated extension, which allows remote attackers to
conduct extension-bindings injection attacks by leveraging script access
to a resource that initially has the about:blank URL. (CVE-2016-5149)

WebKit/Source/bindings/modules/v8/V8BindingForModules.cpp in Blink, as
used in Chromium before 53.0.2785.89 on Windows and OS X and before
53.0.2785.92 on Linux, has an Indexed Database (aka IndexedDB) API
implementation that does not properly restrict key-path evaluation,
which allows remote attackers to cause a denial of service
(use-after-free) or possibly have unspecified other impact via crafted
JavaScript code that leverages certain side effects. (CVE-2016-5150)

PDFium in Chromium before 53.0.2785.89 on Windows and OS X and before
53.0.2785.92 on Linux mishandles timers, which allows remote attackers
to cause a denial of service (use-after-free) or possibly have
unspecified other impact via a crafted PDF document, related to
fpdfsdk/javascript/JS_Object.cpp and fpdfsdk/javascript/app.cpp.
(CVE-2016-5151)

Integer overflow in the opj_tcd_get_decoded_tile_size function in tcd.c
in OpenJPEG, as used in PDFium in Chromium before 53.0.2785.89 on
Windows and OS X and before 53.0.2785.92 on Linux, allows remote
attackers to cause a denial of service (heap-based buffer overflow) or
possibly have unspecified other impact via crafted JPEG 2000 data.
(CVE-2016-5152)

The Web Animations implementation in Blink, as used in Chromium before
53.0.2785.89 on Windows and OS X and before 53.0.2785.92 on Linux,
improperly relies on list iteration, which allows remote attackers to
cause a denial of service (use-after-destruction) or possibly have
unspecified other impact via a crafted web site. (CVE-2016-5153)

Multiple heap-based buffer overflows in PDFium, as used in Chromium
before 53.0.2785.89 on Windows and OS X and before 53.0.2785.92 on
Linux, allow remote attackers to cause a denial of service or possibly
have unspecified other impact via a crafted JBig2 image. (CVE-2016-5154)

Chromium before 53.0.2785.89 on Windows and OS X and before 53.0.2785.92
on Linux does not properly validate access to the initial document,
which allows remote attackers to spoof the address bar via a ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~53.0.2785.113~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~53.0.2785.113~1.mga5", rls:"MAGEIA5"))) {
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
