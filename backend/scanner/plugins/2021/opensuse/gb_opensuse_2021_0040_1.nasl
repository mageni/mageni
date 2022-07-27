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
  script_oid("1.3.6.1.4.1.25623.1.0.853716");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2020-15995", "CVE-2020-16043", "CVE-2021-21106", "CVE-2021-21107", "CVE-2021-21108", "CVE-2021-21109", "CVE-2021-21110", "CVE-2021-21111", "CVE-2021-21112", "CVE-2021-21113", "CVE-2021-21114", "CVE-2021-21115", "CVE-2021-21116");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 05:01:22 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2021:0040-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0040-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6P57LOOIW2OJU7P7J5KL7C2XT5WWY2YT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2021:0040-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  - Update to 87.0.4280.141 (boo#1180645)

  - CVE-2021-21106: Use after free in autofill

  - CVE-2021-21107: Use after free in drag and drop

  - CVE-2021-21108: Use after free in media

  - CVE-2021-21109: Use after free in payments

  - CVE-2021-21110: Use after free in safe browsing

  - CVE-2021-21111: Insufficient policy enforcement in WebUI

  - CVE-2021-21112: Use after free in Blink

  - CVE-2021-21113: Heap buffer overflow in Skia

  - CVE-2020-16043: Insufficient data validation in networking

  - CVE-2021-21114: Use after free in audio

  - CVE-2020-15995: Out of bounds write in V8

  - CVE-2021-21115: Use after free in safe browsing

  - CVE-2021-21116: Heap buffer overflow in audio

  - Use main URLs instead of redirects in master preferences");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~87.0.4280.141~lp152.2.60.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~87.0.4280.141~lp152.2.60.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~87.0.4280.141~lp152.2.60.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~87.0.4280.141~lp152.2.60.1", rls:"openSUSELeap15.2"))) {
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