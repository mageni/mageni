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
  script_oid("1.3.6.1.4.1.25623.1.0.883305");
  script_version("2020-12-16T06:26:32+0000");
  script_cve_id("CVE-2020-16012", "CVE-2020-26951", "CVE-2020-26953", "CVE-2020-26956", "CVE-2020-26958", "CVE-2020-26959", "CVE-2020-26960", "CVE-2020-26961", "CVE-2020-26965", "CVE-2020-26968");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2020-12-16 11:44:11 +0000 (Wed, 16 Dec 2020)");
  script_tag(name:"creation_date", value:"2020-12-10 04:00:55 +0000 (Thu, 10 Dec 2020)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2020:5235)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"CESA", value:"2020:5235");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2020-December/048210.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2020:5235 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 78.5.0.

Security Fix(es):

  * Mozilla: Parsing mismatches could confuse and bypass security sanitizer
for chrome privileged code (CVE-2020-26951)

  * Mozilla: Memory safety bugs fixed in Firefox 83 and Firefox ESR 78.5
(CVE-2020-26968)

  * Mozilla: Variable time processing of cross-origin images during drawImage
calls (CVE-2020-16012)

  * Mozilla: Fullscreen could be enabled without displaying the security UI
(CVE-2020-26953)

  * Mozilla: XSS through paste (manual and clipboard API) (CVE-2020-26956)

  * Mozilla: Requests intercepted through ServiceWorkers lacked MIME type
restrictions (CVE-2020-26958)

  * Mozilla: Use-after-free in WebRequestService (CVE-2020-26959)

  * Mozilla: Potential use-after-free in uses of nsTArray (CVE-2020-26960)

  * Mozilla: DoH did not filter IPv4 mapped IP Addresses (CVE-2020-26961)

  * Mozilla: Software keyboards may have remembered typed passwords
(CVE-2020-26965)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~78.5.0~1.el7.centos", rls:"CentOS7"))) {
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