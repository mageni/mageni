# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0175");
  script_cve_id("CVE-2022-48279", "CVE-2023-24021");
  script_tag(name:"creation_date", value:"2023-05-22 04:13:07 +0000 (Mon, 22 May 2023)");
  script_version("2023-05-22T12:17:59+0000");
  script_tag(name:"last_modification", value:"2023-05-22 12:17:59 +0000 (Mon, 22 May 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-03-06 19:14:00 +0000 (Mon, 06 Mar 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0175)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0175");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0175.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31457");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3283");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/SYRTXTOQQI6SB2TLI5QXU76DURSLS4XI/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-mod_security' package(s) announced via the MGASA-2023-0175 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTTP multipart requests were incorrectly parsed and could bypass the Web
Application Firewall (CVE-2022-48279)
Incorrect handling of '\0' bytes in file uploads in ModSecurity may allow
for Web Application Firewall bypasses and buffer over-reads on the Web
Application Firewall when executing rules that read the FILES_TMP_CONTENT
collection. (CVE-2023-24021)");

  script_tag(name:"affected", value:"'apache-mod_security' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"apache-mod_security", rpm:"apache-mod_security~2.9.7~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mlogc", rpm:"mlogc~2.9.7~1.mga8", rls:"MAGEIA8"))) {
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
