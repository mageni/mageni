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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0038");
  script_cve_id("CVE-2015-8980", "CVE-2016-6621");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-11-06 14:30:00 +0000 (Wed, 06 Nov 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0038)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0038");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0038.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=20169");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2016-44/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-1/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-2/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-3/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-4/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-6/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2017-7/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/files/4.4.15.10/");
  script_xref(name:"URL", value:"https://www.phpmyadmin.net/news/2017/1/23/phpmyadmin-466-441510-and-401019-are-released/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-02/msg00015.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'phpmyadmin' package(s) announced via the MGASA-2017-0038 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in setup script (CVE-2016-6621 / PMASA-2016-44).

Open redirect (PMASA-2017-1).

php-gettext code execution (CVE-2015-8980 / PMASA-2017-2).

DOS vulnerability in table editing (PMASA-2017-3).

CSS injection in themes (PMASA-2017-4).

SSRF in replication (PMASA-2017-6).

DOS in replication status (PMASA-2017-7).");

  script_tag(name:"affected", value:"'phpmyadmin' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"phpmyadmin", rpm:"phpmyadmin~4.4.15.10~1.mga5", rls:"MAGEIA5"))) {
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
