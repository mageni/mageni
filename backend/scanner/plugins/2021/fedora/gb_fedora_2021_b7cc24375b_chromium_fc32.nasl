# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.878874");
  script_version("2021-02-05T06:37:30+0000");
  script_cve_id("CVE-2020-16044", "CVE-2021-21118", "CVE-2021-21119", "CVE-2021-21120", "CVE-2021-21121", "CVE-2021-21122", "CVE-2021-21123", "CVE-2021-21124", "CVE-2021-21125", "CVE-2021-21126", "CVE-2021-21127", "CVE-2021-21129", "CVE-2021-21130", "CVE-2021-21131", "CVE-2021-21132", "CVE-2021-21133", "CVE-2021-21134", "CVE-2021-21135", "CVE-2021-21136", "CVE-2021-21137", "CVE-2021-21138", "CVE-2021-21139", "CVE-2021-21140", "CVE-2021-21141", "CVE-2021-21117", "CVE-2021-21128");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-02-05 17:59:24 +0000 (Fri, 05 Feb 2021)");
  script_tag(name:"creation_date", value:"2021-02-01 04:01:49 +0000 (Mon, 01 Feb 2021)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2021-b7cc24375b)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC32");

  script_xref(name:"Advisory-ID", value:"FEDORA-2021-b7cc24375b");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/MORCK4CNMXQRRVVIR72FHFFU77IS4V5O");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2021-b7cc24375b advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 32.");

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

if(release == "FC32") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~88.0.4324.96~1.fc32", rls:"FC32"))) {
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