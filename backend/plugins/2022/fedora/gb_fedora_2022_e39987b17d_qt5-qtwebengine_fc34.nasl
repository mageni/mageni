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
  script_oid("1.3.6.1.4.1.25623.1.0.819651");
  script_version("2022-02-04T08:16:44+0000");
  script_cve_id("CVE-2021-30523", "CVE-2021-30530", "CVE-2021-30534", "CVE-2021-30535", "CVE-2021-30544", "CVE-2021-30551", "CVE-2021-30554", "CVE-2021-30522", "CVE-2021-30536", "CVE-2021-30533", "CVE-2021-30559", "CVE-2021-30556", "CVE-2021-30547", "CVE-2021-30548", "CVE-2021-30553", "CVE-2021-30563", "CVE-2021-30541", "CVE-2021-30568", "CVE-2021-30569", "CVE-2021-30573", "CVE-2021-30587", "CVE-2021-30588", "CVE-2021-30598", "CVE-2021-30599", "CVE-2021-30602", "CVE-2021-30603", "CVE-2021-30604", "CVE-2021-30585", "CVE-2021-30566", "CVE-2021-30560", "CVE-2021-30618", "CVE-2021-30613", "CVE-2021-30625", "CVE-2021-30626", "CVE-2021-30627", "CVE-2021-30628", "CVE-2021-30629", "CVE-2021-30630", "CVE-2021-30633", "CVE-2021-37967", "CVE-2021-37968", "CVE-2021-37971", "CVE-2021-37973", "CVE-2021-37962", "CVE-2021-30616", "CVE-2021-37978", "CVE-2021-37979", "CVE-2021-37980", "CVE-2021-37975", "CVE-2021-37972", "CVE-2021-3517", "CVE-2021-3541", "CVE-2021-38003", "CVE-2021-37987", "CVE-2021-37992", "CVE-2021-37984", "CVE-2021-37993", "CVE-2021-38018", "CVE-2021-38015", "CVE-2021-38009", "CVE-2021-38017", "CVE-2021-38007", "CVE-2021-38019", "CVE-2021-38005", "CVE-2021-38021", "CVE-2021-38010", "CVE-2021-38012", "CVE-2021-38022", "CVE-2021-37989", "CVE-2021-38001", "CVE-2021-37996", "CVE-2021-4057", "CVE-2021-4058", "CVE-2021-4059", "CVE-2021-4062", "CVE-2021-4079", "CVE-2021-4078", "CVE-2021-4098", "CVE-2021-4099", "CVE-2021-4101", "CVE-2021-4102");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-04 11:00:11 +0000 (Fri, 04 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-04 02:03:26 +0000 (Fri, 04 Feb 2022)");
  script_name("Fedora: Security Advisory for qt5-qtwebengine (FEDORA-2022-e39987b17d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC34");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-e39987b17d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TAQAOVT4SUACCJLZJ5TNNXKVBC2JWMPG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'qt5-qtwebengine'
  package(s) announced via the FEDORA-2022-e39987b17d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Qt5 - QtWebEngine components.");

  script_tag(name:"affected", value:"'qt5-qtwebengine' package(s) on Fedora 34.");

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

if(release == "FC34") {

  if(!isnull(res = isrpmvuln(pkg:"qt5-qtwebengine", rpm:"qt5-qtwebengine~5.15.8~2.fc34", rls:"FC34"))) {
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