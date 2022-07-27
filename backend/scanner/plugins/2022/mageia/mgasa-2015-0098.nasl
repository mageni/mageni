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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0098");
  script_cve_id("CVE-2015-2157");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-21 17:04:00 +0000 (Thu, 21 Mar 2019)");

  script_name("Mageia: Security Advisory (MGASA-2015-0098)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0098");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0098.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15394");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped-2.html");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/changes.html");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2015/02/28/4");
  script_xref(name:"URL", value:"https://filezilla-project.org/newsfeed.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'filezilla, putty' package(s) announced via the MGASA-2015-0098 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated putty and filezilla packages fix security vulnerability:

PuTTY suite versions 0.51 to 0.63 fail to clear SSH-2 private key
information from memory when loading and saving key files to disk,
leading to potential disclosure. The issue affects keys stored on disk
in encrypted and unencrypted form, and is present in PuTTY, Plink,
PSCP, PSFTP, Pageant and PuTTYgen (CVE-2015-2157).

The putty package has been updated to version 0.64, fixing this and other
issues. The filezilla package, which contains a bundled version of PuTTY,
has also been updated, to version 3.10.2.");

  script_tag(name:"affected", value:"'filezilla, putty' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"filezilla", rpm:"filezilla~3.10.2~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"putty", rpm:"putty~0.64~1.mga4", rls:"MAGEIA4"))) {
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
