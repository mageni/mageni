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
  script_oid("1.3.6.1.4.1.25623.1.0.853388");
  script_version("2020-09-02T06:38:34+0000");
  script_cve_id("CVE-2018-18751");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-09-02 10:05:23 +0000 (Wed, 02 Sep 2020)");
  script_tag(name:"creation_date", value:"2020-09-02 11:51:09 +0530 (Wed, 02 Sep 2020)");
  script_name("openSUSE: Security Advisory for gettext-runtime (openSUSE-SU-2020:1278-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"openSUSE-SU", value:"2020:1278-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-08/msg00065.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gettext-runtime'
  package(s) announced via the openSUSE-SU-2020:1278-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gettext-runtime fixes the following issues:

  - Fix boo941629-unnessary-rpath-on-standard-path.patch (bsc#941629)

  - Added msgfmt-double-free.patch to fix a double free error
  (CVE-2018-18751 bsc#1113719)

  - Add patch msgfmt-reset-msg-length-after-remove.patch which does reset
  the length of message string after a line has been removed (bsc#1106843)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.2:

  zypper in -t patch openSUSE-2020-1278=1");

  script_tag(name:"affected", value:"'gettext-runtime' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime", rpm:"gettext-runtime~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-debuginfo", rpm:"gettext-runtime-debuginfo~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-debugsource", rpm:"gettext-runtime-debugsource~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-mini", rpm:"gettext-runtime-mini~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-mini-debuginfo", rpm:"gettext-runtime-mini-debuginfo~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-mini-debugsource", rpm:"gettext-runtime-mini-debugsource~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-tools", rpm:"gettext-tools~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-tools-debuginfo", rpm:"gettext-tools-debuginfo~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-tools-mini", rpm:"gettext-tools-mini~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-tools-mini-debuginfo", rpm:"gettext-tools-mini-debuginfo~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-mini-tools-doc", rpm:"gettext-runtime-mini-tools-doc~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-tools-doc", rpm:"gettext-runtime-tools-doc~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-csharp", rpm:"gettext-csharp~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-java", rpm:"gettext-java~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-32bit", rpm:"gettext-runtime-32bit~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gettext-runtime-32bit-debuginfo", rpm:"gettext-runtime-32bit-debuginfo~0.19.8.1~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
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