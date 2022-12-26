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
  script_oid("1.3.6.1.4.1.25623.1.0.884255");
  script_version("2022-12-06T10:11:16+0000");
  script_cve_id("CVE-2022-45403", "CVE-2022-45404", "CVE-2022-45405", "CVE-2022-45406", "CVE-2022-45408", "CVE-2022-45409", "CVE-2022-45410", "CVE-2022-45411", "CVE-2022-45412", "CVE-2022-45416", "CVE-2022-45418", "CVE-2022-45420", "CVE-2022-45421");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-06 10:11:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-01 02:00:57 +0000 (Thu, 01 Dec 2022)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2022:8555)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2022:8555");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2022-November/073660.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2022:8555 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 102.5.0.

Security Fix(es):

  * Mozilla: Service Workers might have learned size of cross-origin media
files (CVE-2022-45403)

  * Mozilla: Fullscreen notification bypass (CVE-2022-45404)

  * Mozilla: Use-after-free in InputStream implementation (CVE-2022-45405)

  * Mozilla: Use-after-free of a JavaScript Realm (CVE-2022-45406)

  * Mozilla: Fullscreen notification bypass via windowName (CVE-2022-45408)

  * Mozilla: Use-after-free in Garbage Collection (CVE-2022-45409)

  * Mozilla: Memory safety bugs fixed in Firefox 107 and Firefox ESR 102.5
(CVE-2022-45421)

  * Mozilla: ServiceWorker-intercepted requests bypassed SameSite cookie
policy (CVE-2022-45410)

  * Mozilla: Cross-Site Tracing was possible via non-standard override
headers (CVE-2022-45411)

  * Mozilla: Symlinks may resolve to partially uninitialized buffers
(CVE-2022-45412)

  * Mozilla: Keystroke Side-Channel Leakage (CVE-2022-45416)

  * Mozilla: Custom mouse cursor could have been drawn over browser UI
(CVE-2022-45418)

  * Mozilla: Iframe contents could be rendered outside the iframe
(CVE-2022-45420)

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

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~102.5.0~2.el7.centos", rls:"CentOS7"))) {
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