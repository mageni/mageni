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
  script_oid("1.3.6.1.4.1.25623.1.0.853665");
  script_version("2021-04-21T07:29:02+0000");
  script_cve_id("CVE-2016-5100");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-04-21 10:10:24 +0000 (Wed, 21 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-16 04:59:18 +0000 (Fri, 16 Apr 2021)");
  script_name("openSUSE: Security Advisory for froxlor (openSUSE-SU-2021:0415-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0415-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/AAUIVTQVXK6DU6ZXURWINSWBU3EBTIT7");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'froxlor'
  package(s) announced via the openSUSE-SU-2021:0415-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for froxlor fixes the following issues:

  - Upstream upgrade to version 0.10.23 (boo#846355)

  - Upstream upgrade to version 0.10.22 (boo#846355)

  - BuildRequire cron as this contains now the cron directories

  - Use %license for COPYING file instead of %doc [boo#1082318]

     Upstream upgrade to version 0.9.40.1 (boo#846355)

     new features besides API that found their way in:

  - 2FA / TwoFactor Authentication for accounts

  - MySQL8 compatibility

  - new implementation of Let&#x27 s Encrypt (acme.sh)

  - customizable error/access log handling for webserver (format, level,
       pipe-to-script, etc.)

  - lots and lots of bugfixes and small enhancements

     Upstream upgrade to version 0.9.39.5 (boo#846355)

  - PHP rand function for random number generation fixed in previous version
       (boo#1025193) CVE-2016-5100

  - upstream upgrade to version 0.9.39 (boo#846355)

  - Add and change of froxlor config files and manual

  - Change Requires to enable use with php7");

  script_tag(name:"affected", value:"'froxlor' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"froxlor", rpm:"froxlor~0.10.23~lp152.4.3.1", rls:"openSUSELeap15.2"))) {
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