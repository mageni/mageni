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
  script_oid("1.3.6.1.4.1.25623.1.0.853540");
  script_version("2020-11-06T08:04:05+0000");
  script_cve_id("CVE-2020-10802", "CVE-2020-10803", "CVE-2020-10804", "CVE-2020-26934", "CVE-2020-26935");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-11-06 11:47:26 +0000 (Fri, 06 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-03 04:01:21 +0000 (Tue, 03 Nov 2020)");
  script_name("openSUSE: Security Advisory for phpMyAdmin (openSUSE-SU-2020:1806-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.1");

  script_xref(name:"openSUSE-SU", value:"2020:1806-1");
  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2020-11/msg00005.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpMyAdmin'
  package(s) announced via the openSUSE-SU-2020:1806-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for phpMyAdmin fixes the following issues:

  phpMyAdmin was updated to 4.9.7 (boo#1177842):

  * Fix two factor authentication that was broken in 4.9.6

  * Fix incompatibilities with older PHP versions

  Update to 4.9.6:

  - Fixed XSS relating to the transformation feature (boo#1177561
  CVE-2020-26934, PMASA-2020-5)

  - Fixed SQL injection vulnerability in SearchController (boo#1177562
  CVE-2020-26935, PMASA-2020-6)

  Update to 4.9.5:

  This is a security release containing several bug fixes.

  * CVE-2020-10804: SQL injection vulnerability in the user accounts page,
  particularly when changing a password (boo#1167335, PMASA-2020-2)

  * CVE-2020-10802: SQL injection vulnerability relating to the search
  feature (boo#1167336, PMASA-2020-3)

  * CVE-2020-10803: SQL injection and XSS having to do with displaying
  results (boo#1167337, PMASA-2020-4)

  * Removing of the 'options' field for the external transformation.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.1:

  zypper in -t patch openSUSE-2020-1806=1

  - openSUSE Backports SLE-15-SP1:

  zypper in -t patch openSUSE-2020-1806=1

  - openSUSE Backports SLE-15:

  zypper in -t patch openSUSE-2020-1806=1");

  script_tag(name:"affected", value:"'phpMyAdmin' package(s) on openSUSE Leap 15.1.");

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

  if(!isnull(res = isrpmvuln(pkg:"phpMyAdmin", rpm:"phpMyAdmin~4.9.7~lp151.2.24.1", rls:"openSUSELeap15.1"))) {
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