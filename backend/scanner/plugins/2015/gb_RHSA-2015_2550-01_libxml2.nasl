###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for libxml2 RHSA-2015:2550-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871514");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-12-08 10:49:09 +0100 (Tue, 08 Dec 2015)");
  script_cve_id("CVE-2015-1819", "CVE-2015-5312", "CVE-2015-7497", "CVE-2015-7498",
                "CVE-2015-7499", "CVE-2015-7500", "CVE-2015-7941", "CVE-2015-7942",
                "CVE-2015-8241", "CVE-2015-8242", "CVE-2015-8317");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for libxml2 RHSA-2015:2550-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The libxml2 library is a development toolbox
  providing the implementation of various XML standards.

Several denial of service flaws were found in libxml2, a library providing
support for reading, modifying, and writing XML and HTML files. A remote
attacker could provide a specially crafted XML or HTML file that, when
processed by an application using libxml2, would cause that application to
use an excessive amount of CPU, leak potentially sensitive information, or
in certain cases crash the application. (CVE-2015-1819, CVE-2015-5312,
CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, CVE-2015-7500 CVE-2015-7941,
CVE-2015-7942, CVE-2015-8241, CVE-2015-8242, CVE-2015-8317, BZ#1213957,
BZ#1281955)

Red Hat would like to thank the GNOME project for reporting CVE-2015-7497,
CVE-2015-7498, CVE-2015-7499, CVE-2015-7500, CVE-2015-8241, CVE-2015-8242,
and CVE-2015-8317. Upstream acknowledges Kostya Serebryany of Google as the
original reporter of CVE-2015-7497, CVE-2015-7498, CVE-2015-7499, and
CVE-2015-7500  Hugh Davenport as the original reporter of CVE-2015-8241 and
CVE-2015-8242  and Hanno Boeck as the original reporter of CVE-2015-8317.
The CVE-2015-1819 issue was discovered by Florian Weimer of Red Hat
Product Security.

All libxml2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect.");
  script_tag(name:"affected", value:"libxml2 on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-December/msg00015.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.9.1~6.el7_2.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-debuginfo", rpm:"libxml2-debuginfo~2.9.1~6.el7_2.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.9.1~6.el7_2.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.9.1~6.el7_2.2", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
