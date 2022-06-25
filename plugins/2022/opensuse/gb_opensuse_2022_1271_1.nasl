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
  script_oid("1.3.6.1.4.1.25623.1.0.854605");
  script_version("2022-04-29T06:36:55+0000");
  script_cve_id("CVE-2021-21290", "CVE-2021-21295", "CVE-2021-37136", "CVE-2021-37137", "CVE-2021-43797");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-04-29 10:20:12 +0000 (Fri, 29 Apr 2022)");
  script_tag(name:"creation_date", value:"2022-04-21 01:01:14 +0000 (Thu, 21 Apr 2022)");
  script_name("openSUSE: Security Advisory for netty (SUSE-SU-2022:1271-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=(openSUSELeap15\.4|openSUSELeap15\.3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2022:1271-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OSRKZNBHTNPBXXEBPZVNKUWSIPPLZXJE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'netty'
  package(s) announced via the SUSE-SU-2022:1271-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for netty fixes the following issues:

  - Updated to version 4.1.75:

  - CVE-2021-37136: Fixed an unrestricted decompressed data size in
         Bzip2Decoder (bsc#1190610).

  - CVE-2021-37137: Fixed an unrestricted chunk length in
         SnappyFrameDecoder, which might lead to excessive memory usage
         (#bsc#1190613).

  - CVE-2021-43797: Fixed a potential HTTP request smuggling issue due to
         insufficient validation against control characters (bsc#1193672).

  - CVE-2021-21290: Fixed an information disclosure via the local system
         temporary directory (bsc#1182103).");

  script_tag(name:"affected", value:"'netty' package(s) on openSUSE Leap 15.3, openSUSE Leap 15.4.");

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

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.75~150200.4.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.75~150200.4.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-poms", rpm:"netty-poms~4.1.75~150200.4.6.2", rls:"openSUSELeap15.4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "openSUSELeap15.3") {

  if(!isnull(res = isrpmvuln(pkg:"netty", rpm:"netty~4.1.75~150200.4.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-javadoc", rpm:"netty-javadoc~4.1.75~150200.4.6.2", rls:"openSUSELeap15.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"netty-poms", rpm:"netty-poms~4.1.75~150200.4.6.2", rls:"openSUSELeap15.3"))) {
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