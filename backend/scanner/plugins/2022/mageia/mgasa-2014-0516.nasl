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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0516");
  script_cve_id("CVE-2013-6668", "CVE-2014-5256");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-01-07 02:59:00 +0000 (Sat, 07 Jan 2017)");

  script_name("Mageia: Security Advisory (MGASA-2014-0516)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0516");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0516.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13383");
  script_xref(name:"URL", value:"http://blog.nodejs.org/2014/07/31/v8-memory-corruption-stack-overflow/");
  script_xref(name:"URL", value:"http://nodejs.org/dist/v0.10.33/docs/changelog.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-August/136333.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the MGASA-2014-0516 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated nodejs package fixes security vulnerabilities:

A memory corruption vulnerability, which results in a denial-of-service, was
identified in the versions of V8 that ship with Node.js 0.8 and 0.10. In
certain circumstances, a particularly deep recursive workload that may trigger
a GC and receive an interrupt may overflow the stack and result in a
segmentation fault. For instance, if your work load involves successive
JSON.parse calls and the parsed objects are significantly deep, you may
experience the process aborting while parsing (CVE-2014-5256).

Multiple unspecified vulnerabilities in Google V8 before 3.24.35.10, as used
in Node.js before 0.10.31, allow attackers to cause a denial of service or
possibly have other impact via unknown vectors (CVE-2013-6668).

The nodejs package has been updated to version 0.10.33 to fix these issues
as well as several other bugs.");

  script_tag(name:"affected", value:"'nodejs' package(s) on Mageia 4.");

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

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"nodejs", rpm:"nodejs~0.10.33~1.mga4", rls:"MAGEIA4"))) {
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
