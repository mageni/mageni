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
  script_oid("1.3.6.1.4.1.25623.1.0.854902");
  script_version("2022-08-17T07:23:27+0000");
  script_cve_id("CVE-2022-32792", "CVE-2022-32816");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-17 07:23:27 +0000 (Wed, 17 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-17 01:04:15 +0000 (Wed, 17 Aug 2022)");
  script_name("openSUSE: Security Advisory for webkit2gtk3 (SUSE-SU-2022:2826-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.4");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:2826-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6GX5PJNXR43PC4SEJ36ZQLP2LV4U4JZD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the SUSE-SU-2022:2826-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for webkit2gtk3 fixes the following issues:

  - Update to version 2.36.5 (bsc#1201980):

  - Add support for PAC proxy in the WebDriver implementation.

  - Fix video playback when loaded through custom URIs, this fixes video
         playback in the Yelp documentation browser.

  - Fix WebKitWebView::context-menu when using GTK4.

  - Fix LTO builds with GCC.

  - Fix several crashes and rendering issues.

  - Security fixes:

  - CVE-2022-32792: Fixed processing maliciously crafted web content may
         lead to arbitrary code execution.

  - CVE-2022-32816: Fixed visiting a website that frames malicious content
         may lead to UI spoofing.");

  script_tag(name:"affected", value:"'webkit2gtk3' package(s) on openSUSE Leap 15.4.");

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

if(release == "openSUSELeap15.4") {

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0.18", rpm:"libjavascriptcoregtk-4.0.18~2.36.5~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.0.18-debuginfo", rpm:"libjavascriptcoregtk-4.0.18-debuginfo~2.36.5~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1.0", rpm:"libjavascriptcoregtk-4.1.0~2.36.5~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-4.1.0-debuginfo", rpm:"libjavascriptcoregtk-4.1.0-debuginfo~2.36.5~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-5.0.0", rpm:"libjavascriptcoregtk-5.0.0~2.36.5~150400.4.9.1", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libjavascriptcoregtk-5.0.0-debuginfo", rpm:"libjavascriptcoregtk-5.0.0-debuginfo~2.36.5~150400.4.9.1", rls:"openSUSELeap15.4"))) {
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
