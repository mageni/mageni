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
  script_oid("1.3.6.1.4.1.25623.1.0.819841");
  script_version("2022-03-24T14:03:56+0000");
  script_cve_id("CVE-2021-22570", "CVE-2022-0096", "CVE-2022-0097", "CVE-2022-0098", "CVE-2022-0099", "CVE-2022-0100", "CVE-2022-0101", "CVE-2022-0102", "CVE-2022-0103", "CVE-2022-0104", "CVE-2022-0105", "CVE-2022-0106", "CVE-2022-0107", "CVE-2022-0108", "CVE-2022-0109", "CVE-2022-0110", "CVE-2022-0111", "CVE-2022-0112", "CVE-2022-0113", "CVE-2022-0114", "CVE-2022-0115", "CVE-2022-0116", "CVE-2022-0117", "CVE-2022-0118", "CVE-2022-0120", "CVE-2022-0789", "CVE-2022-0790", "CVE-2022-0791", "CVE-2022-0792", "CVE-2022-0793", "CVE-2022-0794", "CVE-2022-0795", "CVE-2022-0796", "CVE-2022-0797", "CVE-2022-0798", "CVE-2022-0799", "CVE-2022-0800", "CVE-2022-0801", "CVE-2022-0802", "CVE-2022-0803", "CVE-2022-0804", "CVE-2022-0805", "CVE-2022-0806", "CVE-2022-0807", "CVE-2022-0808", "CVE-2022-0809");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-03-25 11:41:51 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-17 21:35:00 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-03-23 08:33:19 +0000 (Wed, 23 Mar 2022)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2022-d1a15f9cdb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC35");

  script_xref(name:"Advisory-ID", value:"FEDORA-2022-d1a15f9cdb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5PAGL5M2KGYPN3VEQCRJJE6NA7D5YG5X");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2022-d1a15f9cdb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 35.");

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

if(release == "FC35") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~99.0.4844.51~1.fc35", rls:"FC35"))) {
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