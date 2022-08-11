# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.877952");
  script_version("2020-06-12T07:11:22+0000");
  script_cve_id("CVE-2020-10757", "CVE-2020-12888", "CVE-2020-12655", "CVE-2020-10711", "CVE-2020-11884", "CVE-2020-8835", "CVE-2019-19769", "CVE-2020-2732", "CVE-2019-18808", "CVE-2019-18809", "CVE-2019-18811", "CVE-2019-18812", "CVE-2019-16232", "CVE-2019-19082", "CVE-2019-14895", "CVE-2019-14896", "CVE-2019-14897", "CVE-2019-14901", "CVE-2019-19078", "CVE-2019-19077", "CVE-2019-19074", "CVE-2019-19073", "CVE-2019-19072", "CVE-2019-19071", "CVE-2019-19070", "CVE-2019-19068", "CVE-2019-19043", "CVE-2019-19066", "CVE-2019-19046", "CVE-2019-19050", "CVE-2019-19062", "CVE-2019-19064", "CVE-2019-19063", "CVE-2019-19059", "CVE-2019-19058", "CVE-2019-19057", "CVE-2019-19053", "CVE-2019-19056", "CVE-2019-19055", "CVE-2019-19054", "CVE-2019-11135", "CVE-2018-12207", "CVE-2019-0154", "CVE-2019-0155");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-06-12 09:20:35 +0000 (Fri, 12 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-12 03:09:59 +0000 (Fri, 12 Jun 2020)");
  script_name("Fedora: Security Advisory for kernel (FEDORA-2020-203ffedeb5)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC31");

  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IEM47BXZJLODRH5YNNZSAQ2NVM63MYMC");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel'
  package(s) announced via the FEDORA-2020-203ffedeb5 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The kernel meta package");

  script_tag(name:"affected", value:"'kernel' package(s) on Fedora 31.");

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

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.6.16~200.fc31", rls:"FC31"))) {
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