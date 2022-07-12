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
  script_oid("1.3.6.1.4.1.25623.1.0.884214");
  script_version("2022-05-23T12:36:28+0000");
  script_cve_id("CVE-2022-1520", "CVE-2022-29909", "CVE-2022-29911", "CVE-2022-29912", "CVE-2022-29913", "CVE-2022-29914", "CVE-2022-29916", "CVE-2022-29917");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-05-23 12:36:28 +0000 (Mon, 23 May 2022)");
  script_tag(name:"creation_date", value:"2022-05-07 01:00:41 +0000 (Sat, 07 May 2022)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2022:1725)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:1725");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-May/073582.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2022:1725 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 91.9.0.

Security Fix(es):

  * Mozilla: Bypassing permission prompt in nested browsing contexts
(CVE-2022-29909)

  * Mozilla: iframe Sandbox bypass (CVE-2022-29911)

  * Mozilla: Fullscreen notification bypass using popups (CVE-2022-29914)

  * Mozilla: Leaking browser history with CSS variables (CVE-2022-29916)

  * Mozilla: Memory safety bugs fixed in Firefox 100 and Firefox ESR 91.9
(CVE-2022-29917)

  * Mozilla: Reader mode bypassed SameSite cookies (CVE-2022-29912)

  * Mozilla: Speech Synthesis feature not properly disabled (CVE-2022-29913)

  * Mozilla: Incorrect security status shown after viewing an attached email
(CVE-2022-1520)

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~91.9.0~3.el7.centos", rls:"CentOS7"))) {
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