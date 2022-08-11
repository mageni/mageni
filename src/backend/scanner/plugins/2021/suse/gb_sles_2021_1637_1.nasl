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
  script_oid("1.3.6.1.4.1.25623.1.1.4.2021.1637.1");
  script_cve_id("CVE-2020-11078", "CVE-2021-21240");
  script_tag(name:"creation_date", value:"2021-06-09 14:56:38 +0000 (Wed, 09 Jun 2021)");
  script_version("2021-06-18T08:29:58+0000");
  script_tag(name:"last_modification", value:"2021-06-28 10:25:26 +0000 (Mon, 28 Jun 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-12 14:56:00 +0000 (Fri, 12 Feb 2021)");

  script_name("SUSE: Security Advisory (SUSE-SU-2021:1637-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2021:1637-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2021/suse-su-20211637-1/");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/140");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/138");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/issues/18");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/111");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/issues/123");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/117");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/115");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/issues/112");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/110");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/101");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/100");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/97");
  script_xref(name:"URL", value:"https://github.com/httplib2/httplib2/pull/91");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-httplib2' package(s) announced via the SUSE-SU-2021:1637-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for python-httplib2 contains the following fixes:

Security fixes included in this update:
CVE-2021-21240: Fixed a regular expression denial of service via
 malicious header (bsc#1182053).

CVE-2020-11078: Fixed an issue where an attacker could change request
 headers and body (bsc#1171998).

Non security fixes included in this update:
Update in SLE to 0.19.0 (bsc#1182053, CVE-2021-21240)

update to 0.19.0:
 * auth: parse headers using pyparsing instead of regexp
 * auth: WSSE token needs to be string not bytes

update to 0.18.1: (bsc#1171998, CVE-2020-11078)
 * explicit build-backend workaround for pip build isolation bug
 * IMPORTANT security vulnerability CWE-93 CRLF injection Force %xx quote
 of space, CR, LF characters in uri.
 * Ship test suite in source dist

Update to 0.17.1
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

Update to 0.14.0:
 * Python3: PROXY_TYPE_SOCKS5 with str user/pass raised TypeError

version update to 0.13.1 0.13.1
 * Python3: Use no_proxy [link moved to references]
 0.13.0
 * Allow setting TLS max/min versions
 [link moved to references] 0.12.3
 * No changes to library. Distribute py3 wheels. 0.12.1
 * Catch socket timeouts and clear dead connection
 [link moved to references]
 [link moved to references]
 * Officially support Python 3.7 (package metadata)
 [link moved to references] 0.12.0
 * Drop support for Python 3.3
 * ca_certs from environment HTTPLIB2_CA_CERTS or certifi
 [link moved to references]
 * PROXY_TYPE_HTTP with non-empty user/pass raised TypeError: bytes
 required [link moved to references]
 * Revert http:443->https workaround
 [link moved to references]
 * eliminate connection pool read race
 [link moved to references]
 * cache: stronger safename
 [link moved to references] 0.11.3
 * No changes, just reupload of 0.11.2 after fixing automatic release
 conditions in Travis. 0.11.2
 * proxy: py3 NameError basestring
 [link moved to references] 0.11.1
 * Fix HTTP(S)ConnectionWithTimeout AttributeError proxy_info
 [link moved to references] 0.11.0
 * Add DigiCert Global Root G2 serial 033af1e6a711a9a0bb2864b11d09fae5
 [link moved to references]
 * python3 proxy support h... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'python-httplib2' package(s) on SUSE Linux Enterprise Module for Public Cloud 15");

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

if(release == "SLES15.0") {
  if(!isnull(res = isrpmvuln(pkg:"python3-httplib2", rpm:"python3-httplib2~0.19.0~1.8.1", rls:"SLES15.0"))){
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
