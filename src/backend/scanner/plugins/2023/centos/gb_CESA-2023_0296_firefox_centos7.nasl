# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.884269");
  script_version("2023-01-31T10:08:41+0000");
  script_cve_id("CVE-2022-46871", "CVE-2022-46877", "CVE-2023-23598", "CVE-2023-23599", "CVE-2023-23601", "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23605");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-31 10:08:41 +0000 (Tue, 31 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-31 02:01:33 +0000 (Tue, 31 Jan 2023)");
  script_name("CentOS: Security Advisory for firefox (CESA-2023:0296)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:0296");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-January/086353.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2023:0296 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 102.7.0 ESR.

Security Fix(es):

  * Mozilla: libusrsctp library out of date (CVE-2022-46871)

  * Mozilla: Arbitrary file read from GTK drag and drop on Linux
(CVE-2023-23598)

  * Mozilla: Memory safety bugs fixed in Firefox 109 and Firefox ESR 102.7
(CVE-2023-23605)

  * Mozilla: Malicious command could be hidden in devtools output
(CVE-2023-23599)

  * Mozilla: URL being dragged from cross-origin iframe into same tab
triggers navigation (CVE-2023-23601)

  * Mozilla: Content Security Policy wasn't being correctly applied to
WebSockets in WebWorkers (CVE-2023-23602)

  * Mozilla: Fullscreen notification bypass (CVE-2022-46877)

  * Mozilla: Calls to <code>console.log</code> allowed bypassing Content
Security Policy via format directive (CVE-2023-23603)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'firefox' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~102.7.0~1.el7.centos", rls:"CentOS7"))) {
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
