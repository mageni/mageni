# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852699");
  script_version("2019-09-16T07:48:47+0000");
  script_cve_id("CVE-2019-9511", "CVE-2019-9512", "CVE-2019-9513", "CVE-2019-9514", "CVE-2019-9515", "CVE-2019-9516", "CVE-2019-9517", "CVE-2019-9518");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2019-09-16 07:48:47 +0000 (Mon, 16 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-11 02:01:48 +0000 (Wed, 11 Sep 2019)");
  script_name("openSUSE Update for nodejs8 openSUSE-SU-2019:2115-1 (nodejs8)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-09/msg00031.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs8'
  package(s) announced via the openSUSE-SU-2019:2115_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nodejs8 to version 8.16.1 fixes the following issues:

  Security issues fixed:

  - CVE-2019-9511: Fixed HTTP/2 implementations that are vulnerable to
  window size manipulation and stream prioritization manipulation,
  potentially leading to a denial of service (bsc#1146091).

  - CVE-2019-9512: Fixed HTTP/2 flood using PING frames results in unbounded
  memory growth (bsc#1146099).

  - CVE-2019-9513: Fixed HTTP/2 implementation that is vulnerable to
  resource loops, potentially leading to a denial of service.
  (bsc#1146094).

  - CVE-2019-9514: Fixed HTTP/2 implementation that is vulnerable to a reset
  flood, potentially leading to a denial of service (bsc#1146095).

  - CVE-2019-9515: Fixed HTTP/2 flood using SETTINGS frames results in
  unbounded memory growth (bsc#1146100).

  - CVE-2019-9516: Fixed HTTP/2 implementation that is vulnerable to a
  header leak, potentially leading to a denial of service (bsc#1146090).

  - CVE-2019-9517: Fixed HTTP/2 implementations that are vulnerable to
  unconstrained internal data buffering (bsc#1146097).

  - CVE-2019-9518: Fixed HTTP/2 implementation that is vulnerable to a flood
  of empty frames, potentially leading to a denial of service
  (bsc#1146093).

  Bug fixes:

  - Fixed that npm resolves its default config file like in all other
  versions, as /etc/nodejs/npmrc (bsc#1144919).

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2019-2115=1

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2019-2115=1");

  script_tag(name:"affected", value:"'nodejs8' package(s) on openSUSE Leap 15.0.");

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

if(release == "openSUSELeap15.0") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs8", rpm:"nodejs8~8.16.1~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debuginfo", rpm:"nodejs8-debuginfo~8.16.1~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-debugsource", rpm:"nodejs8-debugsource~8.16.1~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-devel", rpm:"nodejs8-devel~8.16.1~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"npm8", rpm:"npm8~8.16.1~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nodejs8-docs", rpm:"nodejs8-docs~8.16.1~lp150.2.19.1", rls:"openSUSELeap15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
