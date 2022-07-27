# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.877164");
  script_version("2020-01-13T11:49:13+0000");
  script_cve_id("CVE-2019-13664", "CVE-2019-13663", "CVE-2019-13662", "CVE-2019-13661", "CVE-2019-13660", "CVE-2019-13659", "CVE-2019-5881", "CVE-2019-5880", "CVE-2019-5879", "CVE-2019-5878", "CVE-2019-5877", "CVE-2019-5876", "CVE-2019-13692", "CVE-2019-13691", "CVE-2019-5875", "CVE-2019-5874", "CVE-2019-5873", "CVE-2019-5872", "CVE-2019-5871", "CVE-2019-5870", "CVE-2019-13683", "CVE-2019-13682", "CVE-2019-13681", "CVE-2019-13680", "CVE-2019-13679", "CVE-2019-13678", "CVE-2019-13677", "CVE-2019-13676", "CVE-2019-13675", "CVE-2019-13674", "CVE-2019-13673", "CVE-2019-13671", "CVE-2019-13670", "CVE-2019-13669", "CVE-2019-13668", "CVE-2019-13667", "CVE-2019-13666", "CVE-2019-13665");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-01-13 11:49:13 +0000 (Mon, 13 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 07:29:10 +0000 (Thu, 09 Jan 2020)");
  script_name("Fedora Update for chromium FEDORA-2019-9a5e81214f");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BXZDO7L2ACMOYMBUKHPK35DGYAB525ZJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2019-9a5e81214f advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 31.");

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

if(release == "FC31") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~77.0.3865.120~1.fc31", rls:"FC31"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);