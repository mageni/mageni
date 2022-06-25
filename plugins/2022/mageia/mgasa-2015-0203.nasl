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
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0203");
  script_cve_id("CVE-2014-4907", "CVE-2014-4908");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2022-01-28T10:58:44+0000");
  script_tag(name:"last_modification", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2014-07-17 05:07:00 +0000 (Thu, 17 Jul 2014)");

  script_name("Mageia: Security Advisory (MGASA-2015-0203)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0203");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0203.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13740");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-July/135371.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'pnp4nagios' package(s) announced via the MGASA-2015-0203 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated pnp4nagios package fixes security vulnerabilities:

Cross-site scripting (XSS) vulnerability in
share/pnp/application/views/kohana_error_page.php in PNP4Nagios before 0.6.22
allows remote attackers to inject arbitrary web script or HTML via a parameter
that is not properly handled in an error message (CVE-2014-4907).

Multiple cross-site scripting (XSS) vulnerabilities in PNP4Nagios through
0.6.22 allow remote attackers to inject arbitrary web script or HTML via the
URI used for reaching share/pnp/application/views/kohana_error_page.php or
share/pnp/application/views/template.php, leading to improper handling within
an http-equiv='refresh' META element (CVE-2014-4908).");

  script_tag(name:"affected", value:"'pnp4nagios' package(s) on Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"pnp4nagios", rpm:"pnp4nagios~0.6.25~1.1.mga4", rls:"MAGEIA4"))) {
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
