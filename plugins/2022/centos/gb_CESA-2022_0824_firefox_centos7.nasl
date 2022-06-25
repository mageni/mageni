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
  script_oid("1.3.6.1.4.1.25623.1.0.884213");
  script_version("2022-03-31T07:10:52+0000");
  script_cve_id("CVE-2022-25235", "CVE-2022-25236", "CVE-2022-25315", "CVE-2022-26381", "CVE-2022-26383", "CVE-2022-26384", "CVE-2022-26386", "CVE-2022-26387", "CVE-2022-26485", "CVE-2022-26486");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-31 10:53:41 +0000 (Thu, 31 Mar 2022)");
  script_tag(name:"creation_date", value:"2022-03-30 01:01:15 +0000 (Wed, 30 Mar 2022)");
  script_name("CentOS: Security Advisory for firefox (CESA-2022:0824)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:0824");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-March/073578.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2022:0824 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 91.7.0 ESR.

Security Fix(es):

  * Mozilla: Use-after-free in XSLT parameter processing (CVE-2022-26485)

  * Mozilla: Use-after-free in WebGPU IPC Framework (CVE-2022-26486)

  * expat: Malformed 2- and 3-byte UTF-8 sequences can lead to arbitrary code
execution (CVE-2022-25235)

  * expat: Namespace-separator characters in 'xmlns[:prefix]' attribute
values can lead to arbitrary code execution (CVE-2022-25236)

  * expat: Integer overflow in storeRawNames() (CVE-2022-25315)

  * Mozilla: Use-after-free in text reflows (CVE-2022-26381)

  * Mozilla: Browser window spoof using fullscreen mode (CVE-2022-26383)

  * Mozilla: iframe allow-scripts sandbox bypass (CVE-2022-26384)

  * Mozilla: Time-of-check time-of-use bug when verifying add-on signatures
(CVE-2022-26387)

  * Mozilla: Temporary files downloaded to /tmp and accessible by other local
users (CVE-2022-26386)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.

Bug Fix(es):

  * Firefox 91.3.0-1 Language packs installed at /usr/lib64/firefox/langpacks
cannot be used any more (BZ#2030190)");

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

  if(!isnull(res = isrpmvuln(pkg:"firefox", rpm:"firefox~91.7.0~3.el7.centos", rls:"CentOS7"))) {
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