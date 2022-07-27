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
  script_oid("1.3.6.1.4.1.25623.1.0.820817");
  script_version("2022-07-07T10:16:06+0000");
  script_cve_id("CVE-2022-1633", "CVE-2022-1634", "CVE-2022-1635", "CVE-2022-1636", "CVE-2022-1637", "CVE-2022-1638", "CVE-2022-1639", "CVE-2022-1640", "CVE-2022-1641", "CVE-2022-1853", "CVE-2022-1854", "CVE-2022-1855", "CVE-2022-1856", "CVE-2022-1857", "CVE-2022-1858", "CVE-2022-1859", "CVE-2022-1860", "CVE-2022-1861", "CVE-2022-1862", "CVE-2022-1863", "CVE-2022-1864", "CVE-2022-1865", "CVE-2022-1866", "CVE-2022-1867", "CVE-2022-1868", "CVE-2022-1869", "CVE-2022-1870", "CVE-2022-1871", "CVE-2022-1872", "CVE-2022-1873", "CVE-2022-1874", "CVE-2022-1875", "CVE-2022-1876");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-07-07 10:16:06 +0000 (Thu, 07 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-06-30 08:27:53 +0000 (Thu, 30 Jun 2022)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2022-7416607232)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-7416607232");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EGMF5WVZNSCS24CVYSWRSYNQ5RNSJ2RA");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2022-7416607232 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~102.0.5005.115~1.fc36", rls:"FC36"))) {
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