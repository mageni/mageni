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
  script_oid("1.3.6.1.4.1.25623.1.0.875883");
  script_version("2019-05-14T05:04:40+0000");
  script_cve_id("CVE-2018-6055", "CVE-2018-6119", "CVE-2018-16429", "CVE-2018-16428", "CVE-2018-16087", "CVE-2018-16088", "CVE-2018-16086", "CVE-2018-16065", "CVE-2018-16066", "CVE-2018-16067", "CVE-2018-16068", "CVE-2018-16069", "CVE-2018-16070", "CVE-2018-16071", "CVE-2018-16072", "CVE-2018-16073", "CVE-2018-16074", "CVE-2018-16075", "CVE-2018-16076", "CVE-2018-16077", "CVE-2018-16078", "CVE-2018-16085", "CVE-2018-16084", "CVE-2018-16083", "CVE-2018-16082", "CVE-2018-16081", "CVE-2018-16080", "CVE-2018-16079", "CVE-2018-17459", "CVE-2018-17458");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-14 05:04:40 +0000 (Tue, 14 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-07 02:25:11 +0000 (Tue, 07 May 2019)");
  script_name("Fedora Update for chromium FEDORA-2018-39be36e9fc");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC29");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2TV2SXSQSQEUINVLP3BFQ74HLOKOH6TZ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2018-39be36e9fc advisory.");

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

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~69.0.3497.100~1.fc29", rls:"FC29"))) {
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
