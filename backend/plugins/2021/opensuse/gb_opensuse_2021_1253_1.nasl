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
  script_oid("1.3.6.1.4.1.25623.1.0.854164");
  script_version("2021-09-22T08:01:20+0000");
  script_cve_id("CVE-2021-32766", "CVE-2021-32800", "CVE-2021-32801", "CVE-2021-32802");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-22 10:15:34 +0000 (Wed, 22 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-09-14 16:54:00 +0000 (Tue, 14 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-15 01:01:48 +0000 (Wed, 15 Sep 2021)");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2021:1253-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1253-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KTAQAEILOXFUPY3SZFAMY4NQGD5OXQX3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2021:1253-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud fixes the following issues:

     Update to 20.0.12

     Fix boo#1190291

  - CVE-2021-32766 (CWE-209): Generation of Error Message Containing
       Sensitive Information

  - CVE-2021-32800 (CWE-306): Missing Authentication for Critical Function

  - CVE-2021-32801 (CWE-532): Insertion of Sensitive Information into Log
       File

  - CVE-2021-32802 (CWE-829): Inclusion of Functionality from Untrusted
       Control Sphere

     Changes:

  - Bump vue-router from 3.4.3 to 3.4.9 (server#27224)

  - Bump v-click-outside from 3.1.1 to 3.1.2 (server#27232)

  - Bump url-search-params-polyfill from 8.1.0 to 8.1.1 (server#27236)

  - Bump debounce from 1.2.0 to 1.2.1 (server#27646)

  - Bump vue and vue-template-compiler (server#27701)

  - Design fixes to app-settings button (server#27745)

  - Reset checksum when writing files to object store (server#27754)

  - Run s3 tests again (server#27804)

  - Fix in locking cache check (server#27829)

  - Bump dompurify from 2.2.8 to 2.2.9 (server#27836)

  - Make search popup usable on mobile, too (server#27858)

  - Cache images on browser (server#27863)

  - Fix dark theme on public link shares (server#27895)

  - Make user status usable on mobile (server#27897)

  - Do not escape display name in dashboard welcome text (server#27913)

  - Bump moment-timezone from 0.5.31 to 0.5.33 (server#27924)

  - Fix newfileMenu on public page (server#27941)

  - Fix svg icons disappearing in app navigation when text overflows
       (server#27955)

  - Bump bootstrap from 4.5.2 to 4.5.3 (server#27965)

  - Show registered breadcrumb detail views in breadcrumb menu (server#27970)

  - Fix regression in file sidebar (server#27976)

  - Bump exports-loader from 1.1.0 to 1.1.1 (server#27984)

  - Bump @nextcloud/capabilities from 1.0.2 to 1.0.4 (server#27985)

  - Bump @nextcloud/vue-dashboard from 1.0.0 to 1.0.1 (server#27988)

  - Improve notcreatable permissions hint (server#28006)

  - Update CRL due to revoked twofactor_nextcloud_notification.crt
       (server#28018)

  - Bump sass-loader from 10.0.2 to 10.0.5 (server#28032)

  - Increase footer height for longer menus (server#28045)

  - Mask password for Redis and RedisCluster on connection failure
       (server#28054)

  - Fix missing theming for login button (server#28065)

  - Fix overlapping of elements in certain views (server#28072)

  - Disable HEIC image preview provider for performance concerns
       (server#28081)

  - Improve provider check (server#28087)

  - Sanitize more functio ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'nextcloud' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~20.0.12~lp152.3.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-apache", rpm:"nextcloud-apache~20.0.12~lp152.3.12.1", rls:"openSUSELeap15.2"))) {
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
