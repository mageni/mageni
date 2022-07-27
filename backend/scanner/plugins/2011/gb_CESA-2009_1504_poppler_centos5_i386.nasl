###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for poppler CESA-2009:1504 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016271.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880859");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-3603", "CVE-2009-3608", "CVE-2009-3609");
  script_name("CentOS Update for poppler CESA-2009:1504 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'poppler'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"poppler on CentOS 5");
  script_tag(name:"insight", value:"Poppler is a Portable Document Format (PDF) rendering library, used by
  applications such as Evince.

  Multiple integer overflow flaws were found in poppler. An attacker could
  create a malicious PDF file that would cause applications that use poppler
  (such as Evince) to crash or, potentially, execute arbitrary code when
  opened. (CVE-2009-3603, CVE-2009-3608, CVE-2009-3609)

  Red Hat would like to thank Chris Rohlf for reporting the CVE-2009-3608
  issue.

  This update also corrects a regression introduced in the previous poppler
  security update, RHSA-2009:0480, that prevented poppler from rendering
  certain PDF documents correctly. (BZ#528147)

  Users are advised to upgrade to these updated packages, which contain
  backported patches to resolve these issues.");
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

  if ((res = isrpmvuln(pkg:"poppler", rpm:"poppler~0.5.4~4.4.el5_4.11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-devel", rpm:"poppler-devel~0.5.4~4.4.el5_4.11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"poppler-utils", rpm:"poppler-utils~0.5.4~4.4.el5_4.11", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
