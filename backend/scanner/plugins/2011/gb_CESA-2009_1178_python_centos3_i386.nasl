###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for python CESA-2009:1178 centos3 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-July/016040.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880715");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1679", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-4864", "CVE-2008-5031");
  script_name("CentOS Update for python CESA-2009:1178 centos3 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS3");
  script_tag(name:"affected", value:"python on CentOS 3");
  script_tag(name:"insight", value:"Python is an interpreted, interactive, object-oriented programming
  language.

  When the assert() system call was disabled, an input sanitization flaw was
  revealed in the Python string object implementation that led to a buffer
  overflow. The missing check for negative size values meant the Python
  memory allocator could allocate less memory than expected. This could
  result in arbitrary code execution with the Python interpreter's
  privileges. (CVE-2008-1887)

  Multiple buffer and integer overflow flaws were found in the Python Unicode
  string processing and in the Python Unicode and string object
  implementations. An attacker could use these flaws to cause a denial of
  service (Python application crash). (CVE-2008-3142, CVE-2008-5031)

  Multiple integer overflow flaws were found in the Python imageop module. If
  a Python application used the imageop module to process untrusted images,
  it could cause the application to crash or, potentially, execute arbitrary
  code with the Python interpreter's privileges. (CVE-2008-1679,
  CVE-2008-4864)

  Multiple integer underflow and overflow flaws were found in the Python
  snprintf() wrapper implementation. An attacker could use these flaws to
  cause a denial of service (memory corruption). (CVE-2008-3144)

  Multiple integer overflow flaws were found in various Python modules. An
  attacker could use these flaws to cause a denial of service (Python
  application crash). (CVE-2008-2315, CVE-2008-3143)

  Red Hat would like to thank David Remahl of the Apple Product Security team
  for responsibly reporting the CVE-2008-1679 and CVE-2008-2315 issues.

  All Python users should upgrade to these updated packages, which contain
  backported patches to correct these issues.");
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

  if ((res = isrpmvuln(pkg:"python", rpm:"python~2.2.3~6.11", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-devel", rpm:"python-devel~2.2.3~6.11", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-tools", rpm:"python-tools~2.2.3~6.11", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tkinter", rpm:"tkinter~2.2.3~6.11", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-docs", rpm:"python-docs~2.2.3~6.11", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
