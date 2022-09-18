# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.12.2006.297.3");
  script_cve_id("CVE-2006-2775", "CVE-2006-2776", "CVE-2006-2778", "CVE-2006-2779", "CVE-2006-2780", "CVE-2006-2781", "CVE-2006-2783", "CVE-2006-2784", "CVE-2006-2786", "CVE-2006-2787");
  script_tag(name:"creation_date", value:"2022-08-26 07:43:23 +0000 (Fri, 26 Aug 2022)");
  script_version("2022-09-13T14:14:11+0000");
  script_tag(name:"last_modification", value:"2022-09-13 14:14:11 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("Ubuntu: Security Advisory (USN-297-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(5\.04|5\.10)");

  script_xref(name:"Advisory-ID", value:"USN-297-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-297-3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-thunderbird' package(s) announced via the USN-297-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-297-1 fixed several vulnerabilities in Thunderbird for the Ubuntu
6.06 LTS release. This update provides the corresponding fixes for
Ubuntu 5.04 and Ubuntu 5.10.

For reference, these are the details of the original USN:

 Jonas Sicking discovered that under some circumstances persisted XUL
 attributes are associated with the wrong URL. A malicious web site
 could exploit this to execute arbitrary code with the privileges of
 the user. (MFSA 2006-35, CVE-2006-2775)

 Paul Nickerson discovered that content-defined setters on an object
 prototype were getting called by privileged UI code. It was
 demonstrated that this could be exploited to run arbitrary web
 script with full user privileges (MFSA 2006-37, CVE-2006-2776).

 Mikolaj Habryn discovered a buffer overflow in the crypto.signText()
 function. By sending an email with malicious JavaScript to an user,
 and that user enabled JavaScript in Thunderbird (which is not the
 default and not recommended), this could potentially be exploited to
 execute arbitrary code with the user's privileges. (MFSA 2006-38,
 CVE-2006-2778)

 The Mozilla developer team discovered several bugs that lead to
 crashes with memory corruption. These might be exploitable by
 malicious web sites to execute arbitrary code with the privileges of
 the user. (MFSA 2006-32, CVE-2006-2779, CVE-2006-2780)

 Masatoshi Kimura discovered a memory corruption (double-free) when
 processing a large VCard with invalid base64 characters in it. By
 sending a maliciously crafted set of VCards to a user, this could
 potentially be exploited to execute arbitrary code with the user's
 privileges. (MFSA 2006-40, CVE-2006-2781)

 Masatoshi Kimura found a way to bypass web input sanitizers which
 filter out JavaScript. By inserting 'Unicode Byte-order-Mark (BOM)'
 characters into the HTML code (e. g. '<scr[BOM]ipt>'), these filters
 might not recognize the tags anymore, however, Thunderbird would
 still execute them since BOM markers are filtered out before
 processing a mail containing JavaScript. (MFSA 2006-42,
 CVE-2006-2783)

 Kazuho Oku discovered various ways to perform HTTP response
 smuggling when used with certain proxy servers. Due to different
 interpretation of nonstandard HTTP headers in Thunderbird and the
 proxy server, a malicious HTML email can exploit this to send back
 two responses to one request. The second response could be used to
 steal login cookies or other sensitive data from another opened web
 site. (MFSA 2006-33, CVE-2006-2786)

 It was discovered that JavaScript run via EvalInSandbox() can escape
 the sandbox. Malicious scripts received in emails containing
 JavaScript could use these privileges to execute arbitrary code with
 the user's privileges. (MFSA 2006-31, CVE-2006-2787)");

  script_tag(name:"affected", value:"'mozilla-thunderbird' package(s) on Ubuntu 5.04, Ubuntu 5.10.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "UBUNTU5.04") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.8-0ubuntu05.04.1", rls:"UBUNTU5.04"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU5.10") {

  if(!isnull(res = isdpkgvuln(pkg:"mozilla-thunderbird", ver:"1.0.8-0ubuntu05.10.2", rls:"UBUNTU5.10"))) {
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
