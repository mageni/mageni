###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2009:1205 centos3 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-August/016066.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880842");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1891", "CVE-2009-2412");
  script_name("CentOS Update for httpd CESA-2009:1205 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'httpd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"httpd on CentOS 3");
  script_tag(name:"insight", value:"The Apache HTTP Server is a popular Web server. The httpd package shipped
  with Red Hat Enterprise Linux 3 contains embedded copies of the Apache
  Portable Runtime (APR) libraries, which provide a free library of C data
  structures and routines, and also additional utility interfaces to support
  XML parsing, LDAP, database interfaces, URI parsing, and more.

  Multiple integer overflow flaws, leading to heap-based buffer overflows,
  were found in the way the Apache Portable Runtime (APR) manages memory pool
  and relocatable memory allocations. An attacker could use these flaws to
  issue a specially-crafted request for memory allocation, which would lead
  to a denial of service (application crash) or, potentially, execute
  arbitrary code with the privileges of an application using the APR
  libraries. (CVE-2009-2412)

  A denial of service flaw was found in the Apache mod_deflate module. This
  module continued to compress large files until compression was complete,
  even if the network connection that requested the content was closed
  before compression completed. This would cause mod_deflate to consume
  large amounts of CPU if mod_deflate was enabled for a large file.
  (CVE-2009-1891)

  This update also fixes the following bug:

  * in some cases the Content-Length header was dropped from HEAD responses.
  This resulted in certain sites not working correctly with mod_proxy, such
  as www.windowsupdate.com. (BZ#506016)

  All httpd users should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing the updated
  packages, the httpd daemon must be restarted for the update to take effect.");
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

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.0.46~75.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.0.46~75.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.0.46~75.ent.centos", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
