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
  script_oid("1.3.6.1.4.1.25623.1.0.853782");
  script_version("2021-05-10T06:49:03+0000");
  script_cve_id("CVE-2021-21201", "CVE-2021-21202", "CVE-2021-21203", "CVE-2021-21204", "CVE-2021-21205", "CVE-2021-21207", "CVE-2021-21208", "CVE-2021-21209", "CVE-2021-21210", "CVE-2021-21211", "CVE-2021-21212", "CVE-2021-21213", "CVE-2021-21221", "CVE-2021-21222", "CVE-2021-21223", "CVE-2021-21224", "CVE-2021-21225", "CVE-2021-21226", "CVE-2021-21227", "CVE-2021-21228", "CVE-2021-21229", "CVE-2021-21230", "CVE-2021-21231", "CVE-2021-21232", "CVE-2021-21233");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-05-10 10:15:03 +0000 (Mon, 10 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-01 03:01:34 +0000 (Sat, 01 May 2021)");
  script_name("openSUSE: Security Advisory for Chromium (openSUSE-SU-2021:0629-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0629-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/NBOWNTMQCMDYBSMTERFTO5ZSZSUCY7QW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'Chromium'
  package(s) announced via the openSUSE-SU-2021:0629-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - Chromium was updated to 90.0.4430.93
       (boo#1184764, boo#1185047, boo#1185398)

  * CVE-2021-21227: Insufficient data validation in V8.

  * CVE-2021-21232: Use after free in Dev Tools.

  * CVE-2021-21233: Heap buffer overflow in ANGLE.

  * CVE-2021-21228: Insufficient policy enforcement in extensions.

  * CVE-2021-21229: Incorrect security UI in downloads.

  * CVE-2021-21230: Type Confusion in V8.

  * CVE-2021-21231: Insufficient data validation in V8.

  * CVE-2021-21222: Heap buffer overflow in V8

  * CVE-2021-21223: Integer overflow in Mojo

  * CVE-2021-21224: Type Confusion in V8

  * CVE-2021-21225: Out of bounds memory access in V8

  * CVE-2021-21226: Use after free in navigation

  * CVE-2021-21201: Use after free in permissions

  * CVE-2021-21202: Use after free in extensions

  * CVE-2021-21203: Use after free in Blink

  * CVE-2021-21204: Use after free in Blink

  * CVE-2021-21205: Insufficient policy enforcement in navigation

  * CVE-2021-21221: Insufficient validation of untrusted input in Mojo

  * CVE-2021-21207: Use after free in IndexedDB

  * CVE-2021-21208: Insufficient data validation in QR scanner

  * CVE-2021-21209: Inappropriate implementation in storage

  * CVE-2021-21210: Inappropriate implementation in Network

  * CVE-2021-21211: Inappropriate implementation in Navigatio

  * CVE-2021-21212: Incorrect security UI in Network Config UI

  * CVE-2021-21213: Use after free in WebMIDI");

  script_tag(name:"affected", value:"'Chromium' package(s) on openSUSE Leap 15.2.");

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

if(release == "openSUSELeap15.2") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~90.0.4430.93~lp152.2.89.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~90.0.4430.93~lp152.2.89.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~90.0.4430.93~lp152.2.89.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~90.0.4430.93~lp152.2.89.1", rls:"openSUSELeap15.2"))) {
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