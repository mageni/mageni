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
  script_oid("1.3.6.1.4.1.25623.1.0.853830");
  script_version("2021-05-25T12:16:58+0000");
  script_cve_id("CVE-2020-11078", "CVE-2021-21240");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-05-26 10:26:09 +0000 (Wed, 26 May 2021)");
  script_tag(name:"creation_date", value:"2021-05-24 03:01:36 +0000 (Mon, 24 May 2021)");
  script_name("openSUSE: Security Advisory for python-httplib2 (openSUSE-SU-2021:0772-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.2");

  script_xref(name:"Advisory-ID", value:"openSUSE-SU-2021:0772-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ANZIEBB4AJVGYC2KYDE7RDSTFBBTL5ID");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-httplib2'
  package(s) announced via the openSUSE-SU-2021:0772-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-httplib2 contains the following fixes:

     Security fixes included in this update:

  - CVE-2021-21240: Fixed a regular expression denial of service via
       malicious header (bsc#1182053).

  - CVE-2020-11078: Fixed an issue where an attacker could change request
       headers and body (bsc#1171998).

     Non security fixes included in this update:

  - Update in SLE to 0.19.0 (bsc#1182053, CVE-2021-21240)

  - update to 0.19.0:

  * auth: parse headers using pyparsing instead of regexp

  * auth: WSSE token needs to be string not bytes

  - update to 0.18.1: (bsc#1171998, CVE-2020-11078)

  * explicit build-backend workaround for pip build isolation bug

  * IMPORTANT security vulnerability CWE-93 CRLF injection Force %xx quote
         of space, CR, LF characters in uri.

  * Ship test suite in source dist

  - Update to 0.17.1

  * python3: no_proxy was not checked with https

  * feature: Http().redirect_codes set, works after follow(_all)_redirects
         check This allows one line workaround for old gcloud library that uses
         308 response without redirect semantics.

  * IMPORTANT cache invalidation change, fix 307 keep method, add 308
         Redirects

  * proxy: username/password as str compatible with pysocks

  * python2: regression in connect() error handling

  * add support for password protected certificate files

  * feature: Http.close() to clean persistent connections and sensitive
         data

  - Update to 0.14.0:

  * Python3: PROXY_TYPE_SOCKS5 with str user/pass raised TypeError

  - version update to 0.13.1 0.13.1

  * No changes to library. Distribute py3 wheels. 0.12.1


  * Officially support Python 3.7 (package metadata)

  * Drop support for Python 3.3

  * ca_certs  ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'python-httplib2' package(s) on openSUSE Leap 15.2.");

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

  if(!isnull(res = isrpmvuln(pkg:"python2-httplib2", rpm:"python2-httplib2~0.19.0~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-httplib2", rpm:"python3-httplib2~0.19.0~lp152.6.3.1", rls:"openSUSELeap15.2"))) {
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
