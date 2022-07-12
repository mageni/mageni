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
  script_oid("1.3.6.1.4.1.25623.1.0.854006");
  script_version("2021-07-23T08:38:39+0000");
  script_cve_id("CVE-2020-8293", "CVE-2020-8294", "CVE-2020-8295", "CVE-2021-32678", "CVE-2021-32679", "CVE-2021-32680", "CVE-2021-32688", "CVE-2021-32703", "CVE-2021-32705", "CVE-2021-32725", "CVE-2021-32726", "CVE-2021-32734", "CVE-2021-32741");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-07-26 10:31:37 +0000 (Mon, 26 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-21 03:02:34 +0000 (Wed, 21 Jul 2021)");
  script_name("openSUSE: Security Advisory for nextcloud (openSUSE-SU-2021:1068-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1068-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XBA6BUWCG7GXG6XVXJPYJLSFVWJRSYU7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nextcloud'
  package(s) announced via the openSUSE-SU-2021:1068-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for nextcloud fixes the following issues:

     nextcloud was updated to 20.0.11:

  - Fix boo#1188247 - CVE-2021-32678: OCS API response ratelimits are not
       applied

  - Fix boo#1188248 - CVE-2021-32679: filenames where not escaped by default
       in controllers using DownloadResponse

  - Fix boo#1188249 - CVE-2021-32680: share expiration date wasn't properly
       logged

  - Fix boo#1188250 - CVE-2021-32688: lacking permission check with
       application specific tokens

  - Fix boo#1188251 - CVE-2021-32703: lack of ratelimiting on the shareinfo
       endpoint

  - Fix boo#1188252 - CVE-2021-32705: lack of ratelimiting on the public DAV
       endpoint

  - Fix boo#1188253 - CVE-2021-32725: default share permissions were not
       being respected for federated reshares of files and folders

  - Fix boo#1188254 - CVE-2021-32726: webauthn tokens were not deleted after
       a user has been deleted

  - Fix boo#1188255 - CVE-2021-32734: possible full path disclosure on
       shared files

  - Fix boo#1188256 - CVE-2021-32741: lack of ratelimiting on the public
       share link mount endpoint

  - Bump handlebars from 4.7.6 to 4.7.7 (server#26900)

  - Bump lodash from 4.17.20 to 4.17.21 (server#26909)

  - Bump hosted-git-info from 2.8.8 to 2.8.9 (server#26920)

  - Don&#x27 t break OCC if an app is breaking in it&#x27 s Application class
       (server#26954)

  - Add bruteforce protection to the shareinfo endpoint (server#26956)

  - Ignore readonly flag for directories (server#26965)

  - Throttle MountPublicLinkController when share is not found (server#26971)

  - Respect default share permissions for federated reshares (server#27001)

  - Harden apptoken check (server#27014)

  - Use parent wrapper to properly handle moves on the same source/target
       storage (server#27016)

  - Fix error when using CORS with no auth credentials (server#27027)

  - Fix return value of getStorageInfo when &#x27 quota_include_external_storage&#x27
       is enabled (server#27108)

  - Bump patch dependencies (server#27183)

  - Use noreply@ as email address for share emails (server#27209)

  - Bump p-queue from 6.6.1 to 6.6.2 (server#27226)

  - Bump browserslist from 4.14.0 to 4.16.6 (server#27247)

  - Bump webpack from 4.44.1 to 4.44.2 (server#27297)

  - Properly use limit and offset for search in Jail wrapper (server#27308)

  - Make user:report command scale (server#27319)

  - Properly log expiration date removal in audit log (server#27325)

  - Propagate throttling on OCS response (serv ...

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

  if(!isnull(res = isrpmvuln(pkg:"nextcloud", rpm:"nextcloud~20.0.11~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"nextcloud-apache", rpm:"nextcloud-apache~20.0.11~lp152.3.9.1", rls:"openSUSELeap15.2"))) {
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
