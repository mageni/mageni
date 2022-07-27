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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0447");
  script_cve_id("CVE-2018-14349", "CVE-2018-14350", "CVE-2018-14351", "CVE-2018-14352", "CVE-2018-14353", "CVE-2018-14354", "CVE-2018-14355", "CVE-2018-14356", "CVE-2018-14357", "CVE-2018-14358", "CVE-2018-14359", "CVE-2018-14360", "CVE-2018-14361", "CVE-2018-14362", "CVE-2018-14363");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-05-20 01:47:00 +0000 (Wed, 20 May 2020)");

  script_name("Mageia: Security Advisory (MGASA-2018-0447)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA6");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0447");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0447.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=23345");
  script_xref(name:"URL", value:"https://usn.ubuntu.com/3719-1/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2018-08/msg00027.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mutt' package(s) announced via the MGASA-2018-0447 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Mutt incorrectly handled certain requests. An
attacker could possibly use this to execute arbitrary code (CVE-2018-14350,
CVE-2018-14352, CVE-2018-14354, CVE-2018-14359, CVE-2018-14358,
CVE-2018-14353 ,CVE-2018-14357).

It was discovered that Mutt incorrectly handled certain inputs. An attacker
could possibly use this to access or expose sensitive information
(CVE-2018-14355, CVE-2018-14356, CVE-2018-14351, CVE-2018-14362,
CVE-2018-14349).

nntp_add_group in newsrc.c has a stack-based buffer overflow because of
incorrect sscanf usage (CVE-2018-14360).

nntp.c proceeds even if memory allocation fails for messages data
(CVE-2018-14361).

newsrc.c does not properlyrestrict '/' characters that may have unsafe
interaction with cache pathnames (CVE-2018-14363).");

  script_tag(name:"affected", value:"'mutt' package(s) on Mageia 6.");

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

if(release == "MAGEIA6") {

  if(!isnull(res = isrpmvuln(pkg:"mutt", rpm:"mutt~1.10.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-doc", rpm:"mutt-doc~1.10.1~1.1.mga6", rls:"MAGEIA6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"mutt-utf8", rpm:"mutt-utf8~1.10.1~1.1.mga6", rls:"MAGEIA6"))) {
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
