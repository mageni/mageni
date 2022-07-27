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
  script_oid("1.3.6.1.4.1.25623.1.0.884193");
  script_version("2022-01-20T06:32:54+0000");
  script_cve_id("CVE-2021-4140", "CVE-2022-22737", "CVE-2022-22738", "CVE-2022-22739", "CVE-2022-22740", "CVE-2022-22741", "CVE-2022-22742", "CVE-2022-22743", "CVE-2022-22745", "CVE-2022-22747", "CVE-2022-22748", "CVE-2022-22751");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-01-20 06:32:54 +0000 (Thu, 20 Jan 2022)");
  script_tag(name:"creation_date", value:"2022-01-19 02:00:58 +0000 (Wed, 19 Jan 2022)");
  script_name("CentOS: Security Advisory for firefox (CESA-2022:0124)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:0124");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-January/073536.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2022:0124 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 91.5.0 ESR.

Security Fix(es):

  * Mozilla: Iframe sandbox bypass with XSLT (CVE-2021-4140)

  * Mozilla: Race condition when playing audio files (CVE-2022-22737)

  * Mozilla: Heap-buffer-overflow in blendGaussianBlur (CVE-2022-22738)

  * Mozilla: Use-after-free of ChannelEventQueue::mOwner (CVE-2022-22740)

  * Mozilla: Browser window spoof using fullscreen mode (CVE-2022-22741)

  * Mozilla: Out-of-bounds memory access when inserting text in edit mode
(CVE-2022-22742)

  * Mozilla: Browser window spoof using fullscreen mode (CVE-2022-22743)

  * Mozilla: Memory safety bugs fixed in Firefox 96 and Firefox ESR 91.5
(CVE-2022-22751)

  * Mozilla: Leaking cross-origin URLs through securitypolicyviolation event
(CVE-2022-22745)

  * Mozilla: Spoofed origin on external protocol launch dialog
(CVE-2022-22748)

  * Mozilla: Missing throttling on external protocol launch dialog
(CVE-2022-22739)

  * Mozilla: Crash when handling empty pkcs7 sequence (CVE-2022-22747)

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~91.5.0~1.el7.centos", rls:"CentOS7"))) {
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