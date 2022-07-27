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
  script_oid("1.3.6.1.4.1.25623.1.0.852394");
  script_version("2019-04-26T08:24:31+0000");
  script_cve_id("CVE-2018-6196", "CVE-2018-6197", "CVE-2018-6198");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-04-26 08:24:31 +0000 (Fri, 26 Apr 2019)");
  script_tag(name:"creation_date", value:"2019-04-05 02:00:44 +0000 (Fri, 05 Apr 2019)");
  script_name("openSUSE Update for w3m openSUSE-SU-2019:1142-1 (w3m)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2019-04/msg00028.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'w3m'
  package(s) announced via the openSUSE-SU-2019:1142_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for w3m fixes the following issues:

  Security issues fixed:

  - CVE-2018-6196: Prevent infinite recursion in HTMLlineproc0 caused by the
  feed_table_block_tag function which did not prevent a negative indent
  value (bsc#1077559)

  - CVE-2018-6197: Prevent NULL pointer dereference in formUpdateBuffer
  (bsc#1077568)

  - CVE-2018-6198: w3m did not properly handle temporary files when the
  ~/.w3m directory is unwritable, which allowed a local attacker to craft
  a symlink attack to overwrite arbitrary files (bsc#1077572)

  This update was imported from the SUSE:SLE-12:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 42.3:

  zypper in -t patch openSUSE-2019-1142=1");

  script_tag(name:"affected", value:"'w3m' package(s) on openSUSE Leap 42.3.");

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

if(release == "openSUSELeap42.3") {

  if(!isnull(res = isrpmvuln(pkg:"w3m", rpm:"w3m~0.5.3.git20161120~164.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-debuginfo", rpm:"w3m-debuginfo~0.5.3.git20161120~164.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-debugsource", rpm:"w3m-debugsource~0.5.3.git20161120~164.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-inline-image", rpm:"w3m-inline-image~0.5.3.git20161120~164.3.1", rls:"openSUSELeap42.3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"w3m-inline-image-debuginfo", rpm:"w3m-inline-image-debuginfo~0.5.3.git20161120~164.3.1", rls:"openSUSELeap42.3"))) {
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
