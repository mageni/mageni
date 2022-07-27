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
  script_oid("1.3.6.1.4.1.25623.1.0.883620");
  script_version("2022-01-12T14:03:29+0000");
  script_cve_id("CVE-2021-43536", "CVE-2021-43537", "CVE-2021-43538", "CVE-2021-43539", "CVE-2021-43541", "CVE-2021-43542", "CVE-2021-43543", "CVE-2021-43545", "CVE-2021-43546");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-01-13 11:12:56 +0000 (Thu, 13 Jan 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-10 14:08:00 +0000 (Fri, 10 Dec 2021)");
  script_tag(name:"creation_date", value:"2022-01-11 13:39:57 +0000 (Tue, 11 Jan 2022)");
  script_name("CentOS: Security Advisory for firefox (CESA-2021:5014)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2021:5014");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2021-December/060974.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2021:5014 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 91.4.0 ESR.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 95 and Firefox ESR 91.4

  * Mozilla: URL leakage when navigating while executing asynchronous
function (CVE-2021-43536)

  * Mozilla: Heap buffer overflow when using structured clone
(CVE-2021-43537)

  * Mozilla: Missing fullscreen and pointer lock notification when requesting
both (CVE-2021-43538)

  * Mozilla: GC rooting failure when calling wasm instance methods
(CVE-2021-43539)

  * Mozilla: External protocol handler parameters were unescaped
(CVE-2021-43541)

  * Mozilla: XMLHttpRequest error codes could have leaked the existence of an
external protocol handler (CVE-2021-43542)

  * Mozilla: Bypass of CSP sandbox directive when embedding (CVE-2021-43543)

  * Mozilla: Denial of Service when using the Location API in a loop
(CVE-2021-43545)

  * Mozilla: Cursor spoofing could overlay user interface when native cursor
is zoomed (CVE-2021-43546)

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~91.4.0~1.el7.centos", rls:"CentOS7"))) {
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