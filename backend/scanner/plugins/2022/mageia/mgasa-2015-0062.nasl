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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0062");
  script_cve_id("CVE-2015-1209", "CVE-2015-1210", "CVE-2015-1211", "CVE-2015-1212");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-28 15:20:00 +0000 (Mon, 28 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2015-0062)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0062");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0062.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15213");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/01/stable-channel-update_26.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/01/stable-channel-update_30.html");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.com/2015/02/stable-channel-update.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium-browser-stable' package(s) announced via the MGASA-2015-0062 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated chromium-browser packages fix security vulnerabilities:

Use-after-free vulnerability in the
VisibleSelection::nonBoundaryShadowTreeRootNode function in
core/editing/VisibleSelection.cpp in the DOM implementation in Blink, as used
in Google Chrome before 40.0.2214.111 allows remote attackers to cause a
denial of service or possibly have unspecified other impact via crafted
JavaScript code that triggers improper handling of a shadow-root anchor
(CVE-2015-1209).

The V8ThrowException::createDOMException function in
bindings/core/v8/V8ThrowException.cpp in the V8 bindings in Blink, as used in
Google Chrome before 40.0.2214.111 does not properly consider frame access
restrictions during the throwing of an exception, which allows remote
attackers to bypass the Same Origin Policy via a crafted web site
(CVE-2015-1210).

The OriginCanAccessServiceWorkers function in
content/browser/service_worker/service_worker_dispatcher_host.cc in Google
Chrome before 40.0.2214.111 does not properly restrict the URI scheme during
a ServiceWorker registration, which allows remote attackers to gain
privileges via a filesystem: URI (CVE-2015-1211).

Multiple unspecified vulnerabilities in Google Chrome before 40.0.2214.111
allow attackers to cause a denial of service or possibly have other impact
via unknown vectors (CVE-2015-1212).");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser", rpm:"chromium-browser~40.0.2214.111~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-browser-stable", rpm:"chromium-browser-stable~40.0.2214.111~1.mga4", rls:"MAGEIA4"))) {
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
