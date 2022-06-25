###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for jakarta-taglibs-standard CESA-2015:1695 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882269");
  script_version("$Revision: 14095 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-09-02 06:59:45 +0200 (Wed, 02 Sep 2015)");
  script_cve_id("CVE-2015-0254");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for jakarta-taglibs-standard CESA-2015:1695 centos7");
  script_tag(name:"summary", value:"Check the version of jakarta-taglibs-standard");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"jakarta-taglibs-standard is the Java Standard Tag Library (JSTL).
This library is used in conjunction with Tomcat and Java Server Pages
(JSP).

It was found that the Java Standard Tag Library (JSTL) allowed the
processing of untrusted XML documents to utilize external entity
references, which could access resources on the host system and,
potentially, allowing arbitrary code execution. (CVE-2015-0254)

Note: jakarta-taglibs-standard users may need to take additional steps
after applying this update. Detailed instructions on the additional steps
can be at the linked references.

All jakarta-taglibs-standard users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

For details on how to apply this update, refer to the linked article.

5. Bugs fixed:

1198606 - CVE-2015-0254 jakarta-taglibs-standard: XXE and RCE via XSL extension in JSTL XML tags

6. Package List:

Red Hat Enterprise Linux Desktop Optional (v. 6):

Source:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.src.rpm

noarch:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.noarch.rpm
jakarta-taglibs-standard-javadoc-1.1.1-11.7.el6_7.noarch.rpm

Red Hat Enterprise Linux HPC Node Optional (v. 6):

Source:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.src.rpm

noarch:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.noarch.rpm
jakarta-taglibs-standard-javadoc-1.1.1-11.7.el6_7.noarch.rpm

Red Hat Enterprise Linux Server Optional (v. 6):

Source:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.src.rpm

noarch:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.noarch.rpm
jakarta-taglibs-standard-javadoc-1.1.1-11.7.el6_7.noarch.rpm

Red Hat Enterprise Linux Workstation Optional (v. 6):

Source:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.src.rpm

noarch:
jakarta-taglibs-standard-1.1.1-11.7.el6_7.noarch.rpm
jakarta-taglibs-standard-javadoc-1.1.1-11.7.el6_7.noarch.rpm

Red Hat Enterprise Linux Client Optional (v. 7):

Source:
jakarta-taglibs-standard-1.1.2-14.el7_1.src.rpm

noarch:
jakarta-taglibs-standard-1.1.2-14.el7_1.noarch.rpm
jakarta-taglibs-standard-javadoc-1.1.2-14.el7_1.noarch.rpm

Red Hat Enterprise Linux ComputeNode Optional (v. 7):

Source:
jakarta-taglibs-standard-1.1.2-14.el7_1.src.rpm

noarc ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"jakarta-taglibs-standard on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-September/021359.html");
  script_xref(name:"URL", value:"https://access.redhat.com/solutions/1584363");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"jakarta-taglibs-standard", rpm:"jakarta-taglibs-standard~1.1.2~14.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-taglibs-standard-javadoc", rpm:"jakarta-taglibs-standard-javadoc~1.1.2~14.el7_1", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
