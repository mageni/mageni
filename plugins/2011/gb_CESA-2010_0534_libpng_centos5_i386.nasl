###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libpng CESA-2010:0534 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-July/016781.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880574");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-2042", "CVE-2010-0205", "CVE-2010-1205", "CVE-2010-2249");
  script_name("CentOS Update for libpng CESA-2010:0534 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libpng'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libpng on CentOS 5");
  script_tag(name:"insight", value:"The libpng packages contain a library of functions for creating and
  manipulating PNG (Portable Network Graphics) image format files.

  A memory corruption flaw was found in the way applications, using the
  libpng library and its progressive reading method, decoded certain PNG
  images. An attacker could create a specially-crafted PNG image that, when
  opened, could cause an application using libpng to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2010-1205)

  A denial of service flaw was found in the way applications using the libpng
  library decoded PNG images that have certain, highly compressed ancillary
  chunks. An attacker could create a specially-crafted PNG image that could
  cause an application using libpng to consume excessive amounts of memory
  and CPU time, and possibly crash. (CVE-2010-0205)

  A memory leak flaw was found in the way applications using the libpng
  library decoded PNG images that use the Physical Scale (sCAL) extension. An
  attacker could create a specially-crafted PNG image that could cause an
  application using libpng to exhaust all available memory and possibly crash
  or exit. (CVE-2010-2249)

  A sensitive information disclosure flaw was found in the way applications
  using the libpng library processed 1-bit interlaced PNG images. An attacker
  could create a specially-crafted PNG image that could cause an application
  using libpng to disclose uninitialized memory. (CVE-2009-2042)

  Users of libpng and libpng10 should upgrade to these updated packages,
  which contain backported patches to correct these issues. All running
  applications using libpng or libpng10 must be restarted for the update to
  take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
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

  if ((res = isrpmvuln(pkg:"libpng", rpm:"libpng~1.2.10~7.1.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpng-devel", rpm:"libpng-devel~1.2.10~7.1.el5_5.3", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
