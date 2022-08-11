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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0221");
  script_cve_id("CVE-2020-5283");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-15 06:15:00 +0000 (Fri, 15 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0221");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0221.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26628");
  script_xref(name:"URL", value:"https://github.com/viewvc/viewvc/security/advisories/GHSA-xpxf-fvqv-7mfg");
  script_xref(name:"URL", value:"https://github.com/viewvc/viewvc/releases/tag/1.1.27");
  script_xref(name:"URL", value:"https://github.com/viewvc/viewvc/releases/tag/1.1.28");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2Q2STF2MKT24HXZ3YZIU7CN6F6QM67I5/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'viewvc' package(s) announced via the MGASA-2020-0221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated viewvc package fixes security vulnerability:

ViewVC before versions 1.1.28 has an XSS vulnerability in CVS
show_subdir_lastmod support. The impact of this vulnerability is mitigated
by the need for an attacker to have commit privileges to a CVS repository
exposed by an otherwise trusted ViewVC instance that also has the
`show_subdir_lastmod` feature enabled. The attack vector involves files
with unsafe names (names that, when embedded into an HTML stream, would
cause the browser to run unwanted code), which themselves can be
challenging to create (CVE-2020-5283).

The viewvc package has been updated to version 1.1.28, fixing this issue
and other bugs.");

  script_tag(name:"affected", value:"'viewvc' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"viewvc", rpm:"viewvc~1.1.28~1.mga7", rls:"MAGEIA7"))) {
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
