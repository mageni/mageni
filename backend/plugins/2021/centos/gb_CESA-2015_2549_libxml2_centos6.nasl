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
  script_oid("1.3.6.1.4.1.25623.1.0.882334");
  script_version("2021-04-21T15:24:38+0000");
  script_cve_id("CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498", "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942", "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-04-22 10:14:47 +0000 (Thu, 22 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-21 14:10:46 +0000 (Wed, 21 Apr 2021)");
  script_name("CentOS: Security Advisory for libxml2 (CESA-2015:2549)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");

  script_xref(name:"Advisory-ID", value:"CESA-2015:2549");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2015-December/021516.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the CESA-2015:2549 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libxml2 library is a development
toolbox providing the implementation of various XML standards.

Several denial of service flaws were found in libxml2, a library providing
support for reading, modifying, and writing XML and HTML files. A remote
attacker could provide a specially crafted XML or HTML file that, when
processed by an application using libxml2, would cause that application to
use an excessive amount of CPU, leak potentially sensitive information, or
in certain cases crash the application. (CVE-2015-5312, CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, CVE-2015-7500 CVE-2015-7941, CVE-2015-7942,
CVE-2015-8241, CVE-2015-8242, CVE-2015-8317, BZ#1213957, BZ#1281955)

Red Hat would like to thank the GNOME project for reporting CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, CVE-2015-7500, CVE-2015-8241, CVE-2015-8242,
and CVE-2015-8317. Upstream acknowledges Kostya Serebryany of Google as the
original reporter of CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, and
CVE-2015-7500  Hugh Davenport as the original reporter of CVE-2015-8241 and
CVE-2015-8242  and Hanno Boeck as the original reporter of CVE-2015-8317.

All libxml2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect.");

  script_tag(name:"affected", value:"'libxml2' package(s) on CentOS 6.");

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

if(release == "CentOS6") {

  if(!isnull(res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.7.6~20.el6_7.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.7.6~20.el6_7.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.7.6~20.el6_7.1", rls:"CentOS6"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libxml2-static", rpm:"libxml2-static~2.7.6~20.el6_7.1", rls:"CentOS6"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if (__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);