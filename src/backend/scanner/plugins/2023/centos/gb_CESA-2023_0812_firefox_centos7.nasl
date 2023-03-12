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
  script_oid("1.3.6.1.4.1.25623.1.0.884273");
  script_version("2023-03-01T10:09:26+0000");
  script_cve_id("CVE-2023-0767", "CVE-2023-25728", "CVE-2023-25729", "CVE-2023-25730", "CVE-2023-25732", "CVE-2023-25735", "CVE-2023-25737", "CVE-2023-25739", "CVE-2023-25742", "CVE-2023-25743", "CVE-2023-25744", "CVE-2023-25746");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-03-01 10:09:26 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-02-23 02:00:53 +0000 (Thu, 23 Feb 2023)");
  script_name("CentOS: Security Advisory for firefox (CESA-2023:0812)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:0812");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-February/086376.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2023:0812 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 102.8.0 ESR.

Security Fix(es):

  * Mozilla: Arbitrary memory write via PKCS 12 in NSS (CVE-2023-0767)

  * Mozilla: Content security policy leak in violation reports using iframes
(CVE-2023-25728)

  * Mozilla: Screen hijack via browser fullscreen mode (CVE-2023-25730)

  * Mozilla: Potential use-after-free from compartment mismatch in
SpiderMonkey (CVE-2023-25735)

  * Mozilla: Invalid downcast in SVGUtils::SetupStrokeGeometry
(CVE-2023-25737)

  * Mozilla: Use-after-free in
mozilla::dom::ScriptLoadContext::~ScriptLoadContext (CVE-2023-25739)

  * Mozilla: Fullscreen notification not shown in Firefox Focus
(CVE-2023-25743)

  * Mozilla: Memory safety bugs fixed in Firefox 110 and Firefox ESR 102.8
(CVE-2023-25744)

  * Mozilla: Memory safety bugs fixed in Firefox ESR 102.8 (CVE-2023-25746)

  * Mozilla: Extensions could have opened external schemes without user
knowledge (CVE-2023-25729)

  * Mozilla: Out of bounds memory write from EncodeInputStream
(CVE-2023-25732)

  * Mozilla: Web Crypto ImportKey crashes tab (CVE-2023-25742)

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~102.8.0~2.el7.centos", rls:"CentOS7"))) {
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