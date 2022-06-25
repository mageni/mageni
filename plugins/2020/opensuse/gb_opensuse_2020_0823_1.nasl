# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.853216");
  script_version("2020-06-24T03:42:18+0000");
  script_cve_id("CVE-2020-6463", "CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468", "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472", "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476", "CVE-2020-6477", "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481", "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6485", "CVE-2020-6486", "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490", "CVE-2020-6491", "CVE-2020-6493", "CVE-2020-6494", "CVE-2020-6495", "CVE-2020-6496");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-24 03:42:18 +0000 (Wed, 24 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-18 03:00:47 +0000 (Thu, 18 Jun 2020)");
  script_name("openSUSE: Security Advisory for chromium (openSUSE-SU-2020:0823-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:0823-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-06/msg00034.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the openSUSE-SU-2020:0823-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for chromium fixes the following issues:

  Chromium was updated to 83.0.4103.97 (boo#1171910, bsc#1172496):

  * CVE-2020-6463: Use after free in ANGLE (boo#1170107 boo#1171975).

  * CVE-2020-6465: Use after free in reader mode. Reported by Woojin
  Oh(@pwn_expoit) of STEALIEN on 2020-04-21

  * CVE-2020-6466: Use after free in media. Reported by Zhe Jin from cdsrc
  of Qihoo 360 on 2020-04-26

  * CVE-2020-6467: Use after free in WebRTC. Reported by ZhanJia Song on
  2020-04-06

  * CVE-2020-6468: Type Confusion in V8. Reported by Chris Salls and Jake
  Corina of Seaside Security, Chani Jindal of Shellphish on 2020-04-30

  * CVE-2020-6469: Insufficient policy enforcement in developer tools.
  Reported by David Erceg on 2020-04-02

  * CVE-2020-6470: Insufficient validation of untrusted input in clipboard.

  * CVE-2020-6471: Insufficient policy enforcement in developer tools.
  Reported by David Erceg on 2020-03-08

  * CVE-2020-6472: Insufficient policy enforcement in developer tools.
  Reported by David Erceg on 2020-03-25

  * CVE-2020-6473: Insufficient policy enforcement in Blink. Reported by
  Soroush Karami and Panagiotis Ilia on 2020-02-06

  * CVE-2020-6474: Use after free in Blink. Reported by Zhe Jin from cdsrc
  of Qihoo 360 on 2020-03-07

  * CVE-2020-6475: Incorrect security UI in full screen. Reported by Khalil
  Zhani on 2019-10-31

  * CVE-2020-6476: Insufficient policy enforcement in tab strip. Reported by
  Alexandre Le Borgne on 2019-12-18

  * CVE-2020-6477: Inappropriate implementation in installer. Reported by
  RACK911 Labs on 2019-03-26

  * CVE-2020-6478: Inappropriate implementation in full screen. Reported by
  Khalil Zhani on 2019-12-24

  * CVE-2020-6479: Inappropriate implementation in sharing. Reported by
  Zhong Zhaochen of andsecurity.cn on 2020-01-14

  * CVE-2020-6480: Insufficient policy enforcement in enterprise. Reported
  by Marvin Witt on 2020-02-21

  * CVE-2020-6481: Insufficient policy enforcement in URL formatting.
  Reported by Rayyan Bijoora on 2020-04-07

  * CVE-2020-6482: Insufficient policy enforcement in developer tools.
  Reported by Abdulrahman Alqabandi (@qab) on 2017-12-17

  * CVE-2020-6483: Insufficient policy enforcement in payments. Reported by
  Jun Kokatsu, Microsoft Browser Vulnerability Research on 2019-05-23

  * CVE-2020-6484: Insufficient data validation in ChromeDriver. Reported by
  Artem Zinenko on 2020-01-26

  * CVE-2020-6485: Insufficient data validation in media router. Reported by
  Sergei Glazunov of Google Project Zero on 2020-01-30

  * CVE-2020-6486: Ins ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'chromium' package(s) on openSUSE Leap 15.1.");

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

if(release == "openSUSELeap15.1") {

  if(!isnull(res = isrpmvuln(pkg:"chromedriver", rpm:"chromedriver~83.0.4103.97~lp151.2.96.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromedriver-debuginfo", rpm:"chromedriver-debuginfo~83.0.4103.97~lp151.2.96.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~83.0.4103.97~lp151.2.96.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debuginfo", rpm:"chromium-debuginfo~83.0.4103.97~lp151.2.96.1", rls:"openSUSELeap15.1"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"chromium-debugsource", rpm:"chromium-debugsource~83.0.4103.97~lp151.2.96.1", rls:"openSUSELeap15.1"))) {
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
