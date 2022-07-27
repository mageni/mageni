###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for xerces-j2 RHSA-2014:1319-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871252");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-10-01 16:59:21 +0530 (Wed, 01 Oct 2014)");
  script_cve_id("CVE-2013-4002");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("RedHat Update for xerces-j2 RHSA-2014:1319-01");
  script_tag(name:"insight", value:"Apache Xerces for Java (Xerces-J) is a high performance, standards
compliant, validating XML parser written in Java. The xerces-j2 packages
provide Xerces-J version 2.

A resource consumption issue was found in the way Xerces-J handled XML
declarations. A remote attacker could use an XML document with a specially
crafted declaration using a long pseudo-attribute name that, when parsed by
an application using Xerces-J, would cause that application to use an
excessive amount of CPU. (CVE-2013-4002)

All xerces-j2 users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. Applications using the
Xerces-J must be restarted for this update to take effect.");
  script_tag(name:"affected", value:"xerces-j2 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Server (v. 7),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-September/msg00058.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xerces-j2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_(7|6)");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.11.0~17.el7_0", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}


if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"xerces-j2", rpm:"xerces-j2~2.7.1~12.7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xerces-j2-debuginfo", rpm:"xerces-j2-debuginfo~2.7.1~12.7.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
