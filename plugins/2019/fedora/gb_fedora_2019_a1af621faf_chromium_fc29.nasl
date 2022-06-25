# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.876604");
  script_version("2019-07-25T11:54:35+0000");
  script_cve_id("CVE-2019-5805", "CVE-2019-5806", "CVE-2019-5807", "CVE-2019-5808", "CVE-2019-5809", "CVE-2019-5810", "CVE-2019-5811", "CVE-2019-5813", "CVE-2019-5814", "CVE-2019-5815", "CVE-2019-5818", "CVE-2019-5819", "CVE-2019-5820", "CVE-2019-5821", "CVE-2019-5822", "CVE-2019-5824", "CVE-2019-5825", "CVE-2019-5826", "CVE-2019-5827", "CVE-2019-5828", "CVE-2019-5829", "CVE-2019-5830", "CVE-2019-5831", "CVE-2019-5832", "CVE-2019-5833", "CVE-2019-5834", "CVE-2019-5835", "CVE-2019-5836", "CVE-2019-5837", "CVE-2019-5838", "CVE-2019-5839", "CVE-2019-5840", "CVE-2019-5842", "CVE-2019-5823", "CVE-2019-5817", "CVE-2019-5816", "CVE-2019-5812");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-25 11:54:35 +0000 (Thu, 25 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-25 02:18:53 +0000 (Thu, 25 Jul 2019)");
  script_name("Fedora Update for chromium FEDORA-2019-a1af621faf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CPM7VPE27DUNJLXM4F5PAAEFFWOEND6X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2019-a1af621faf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 29.");

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

if(release == "FC29") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~75.0.3770.100~3.fc29", rls:"FC29"))) {
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