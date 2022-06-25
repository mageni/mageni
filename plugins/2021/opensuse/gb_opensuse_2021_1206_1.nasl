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
  script_oid("1.3.6.1.4.1.25623.1.0.854121");
  script_version("2021-09-03T10:01:28+0000");
  script_cve_id("CVE-2020-26137");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-09-03 12:13:43 +0000 (Fri, 03 Sep 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-15 21:15:00 +0000 (Tue, 15 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-08-28 01:02:21 +0000 (Sat, 28 Aug 2021)");
  script_name("openSUSE: Security Advisory for aws-cli, (openSUSE-SU-2021:1206-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:1206-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/6CAFSANHH6TU43VSKAJ5JA2EMHSREMKP");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aws-cli, '
  package(s) announced via the openSUSE-SU-2021:1206-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This patch updates the Python AWS SDK stack in SLE 15:

     General:

     # aws-cli

  - Version updated to upstream release v1.19.9 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-boto3

  - Version updated to upstream release 1.17.9 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-botocore

  - Version updated to upstream release 1.20.9 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-urllib3

  - Version updated to upstream release 1.25.10 For a detailed list of all
       changes, please refer to the changelog file of this package.

     # python-service_identity

  - Added this new package to resolve runtime dependencies for other
       packages. Version: 18.1.0

     # python-trustme

  - Added this new package to resolve runtime dependencies for other
       packages. Version: 0.6.0

     Security fixes:

     # python-urllib3:

  - CVE-2020-26137: urllib3 before 1.25.9 allows CRLF injection if the
       attacker controls the HTTP request method, as demonstrated by inserting
       CR and LF control characters in the first argument of putrequest()
       (bsc#1177120)

     This update was imported from the SUSE:SLE-15-SP2:Update update project.");

  script_tag(name:"affected", value:"'aws-cli, ' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"python-cffi-debuginfo", rpm:"python-cffi-debuginfo~1.13.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cffi-debugsource", rpm:"python-cffi-debugsource~1.13.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debuginfo", rpm:"python-cryptography-debuginfo~2.8~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-cryptography-debugsource", rpm:"python-cryptography-debugsource~2.8~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cffi", rpm:"python2-cffi~1.13.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cffi-debuginfo", rpm:"python2-cffi-debuginfo~1.13.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography", rpm:"python2-cryptography~2.8~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-cryptography-debuginfo", rpm:"python2-cryptography-debuginfo~2.8~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cffi", rpm:"python3-cffi~1.13.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cffi-debuginfo", rpm:"python3-cffi-debuginfo~1.13.2~lp152.2.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography", rpm:"python3-cryptography~2.8~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-cryptography-debuginfo", rpm:"python3-cryptography-debuginfo~2.8~lp152.2.12.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python-pyOpenSSL-doc", rpm:"python-pyOpenSSL-doc~17.5.0~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python2-pyOpenSSL", rpm:"python2-pyOpenSSL~17.5.0~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-pyOpenSSL", rpm:"python3-pyOpenSSL~17.5.0~lp152.7.3.1", rls:"openSUSELeap15.2"))) {
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