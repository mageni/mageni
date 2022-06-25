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
  script_oid("1.3.6.1.4.1.25623.1.0.854442");
  script_version("2022-02-22T06:48:08+0000");
  script_cve_id("CVE-2021-22959", "CVE-2021-22960", "CVE-2021-37701", "CVE-2021-37712", "CVE-2021-37713", "CVE-2021-39134", "CVE-2021-39135");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-02-22 11:21:00 +0000 (Tue, 22 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-08 08:15:58 +0000 (Tue, 08 Feb 2022)");
  script_name("openSUSE: Security Advisory for nodejs14 (openSUSE-SU-2021:1552-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1552-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/INKZHV64GX7LRVL3YYOERQLU3B3U47QD");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs14'
  package(s) announced via the openSUSE-SU-2021:1552-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs14 fixes the following issues:
  nodejs14 was updated to 14.18.1:

  * deps: update llhttp to 2.1.4

  - HTTP Request Smuggling due to spaced in headers (bsc#1191601,
         CVE-2021-22959)

  - HTTP Request Smuggling when parsing the body (bsc#1191602,
         CVE-2021-22960)
  Changes in 14.18.0:

  * buffer:
  + introduce Blob
         + add base64url encoding option

  * child_process:
  + allow options.cwd receive a URL
         + add timeout to spawn and fork
         + allow promisified exec to be cancel
         + add 'overlapped' stdio flag

  * dns: add 'tries' option to Resolve options

  * fs:
  + allow empty string for temp directory prefix
         + allow no-params fsPromises fileHandle read
         + add support for async iterators to fsPromises.writeFile

  * http2: add support for sensitive headers

  * process: add 'worker' event

  * tls: allow reading data into a static buffer

  * worker: add setEnvironmentData/getEnvironmentData
  Changes in 14.17.6

  * deps: upgrade npm to 6.14.15 which fixes a number of security issues
         (bsc#1190057, CVE-2021-37701, bsc#1190056, CVE-2021-37712,
         bsc#1190055, CVE-2021-37713, bsc#1190054, CVE-2021-39134, bsc#1190053,
         CVE-2021-39135)
  This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'nodejs14' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-docs", rpm:"nodejs14-docs~14.18.1~lp152.17.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14", rpm:"nodejs14~14.18.1~lp152.17.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debuginfo", rpm:"nodejs14-debuginfo~14.18.1~lp152.17.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-debugsource", rpm:"nodejs14-debugsource~14.18.1~lp152.17.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs14-devel", rpm:"nodejs14-devel~14.18.1~lp152.17.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm14", rpm:"npm14~14.18.1~lp152.17.1", rls:"openSUSELeap15.2"))) {
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