###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libtiff CESA-2014:0223 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.881890");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-03-04 10:47:23 +0530 (Tue, 04 Mar 2014)");
  script_cve_id("CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for libtiff CESA-2014:0223 centos5");

  script_tag(name:"affected", value:"libtiff on CentOS 5");
  script_tag(name:"insight", value:"The libtiff packages contain a library of functions for manipulating Tagged
Image File Format (TIFF) files.

A heap-based buffer overflow and a use-after-free flaw were found in the
tiff2pdf tool. An attacker could use these flaws to create a specially
crafted TIFF file that would cause tiff2pdf to crash or, possibly, execute
arbitrary code. (CVE-2013-1960, CVE-2013-4232)

Multiple buffer overflow flaws were found in the gif2tiff tool. An attacker
could use these flaws to create a specially crafted GIF file that could
cause gif2tiff to crash or, possibly, execute arbitrary code.
(CVE-2013-4231, CVE-2013-4243, CVE-2013-4244)

Multiple buffer overflow flaws were found in the tiff2pdf tool. An attacker
could use these flaws to create a specially crafted TIFF file that would
cause tiff2pdf to crash. (CVE-2013-1961)

Red Hat would like to thank Emmanuel Bouillon of NCI Agency for reporting
CVE-2013-1960 and CVE-2013-1961. The CVE-2013-4243 issue was discovered by
Murray McAllister of the Red Hat Security Response Team, and the
CVE-2013-4244 issue was discovered by Huzaifa Sidhpurwala of the Red Hat
Security Response Team.

All libtiff users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. All running
applications linked against libtiff must be restarted for this update to
take effect.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to use the
Red Hat Network to apply this update are available at the linked references.");

  script_xref(name:"URL", value:"https://access.redhat.com/site/articles/11258");

  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-February/020180.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'libtiff'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"libtiff", rpm:"libtiff~3.8.2~19.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libtiff-devel", rpm:"libtiff-devel~3.8.2~19.el5_10", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
