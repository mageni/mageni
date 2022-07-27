###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for jakarta-commons-collections CESA-2015:2521 centos6
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
  script_oid("1.3.6.1.4.1.25623.1.0.882333");
  script_version("$Revision: 14095 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-12-03 06:32:59 +0100 (Thu, 03 Dec 2015)");
  script_cve_id("CVE-2015-7501");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for jakarta-commons-collections CESA-2015:2521 centos6");

  script_xref(name:"URL", value:"https://access.redhat.com/solutions/2045023");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");

  script_tag(name:"summary", value:"Check the version of jakarta-commons-collections");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The Jakarta/Apache Commons Collections
library provides new interfaces, implementations, and utilities to extend the
features of the Java Collections Framework.

It was found that the Apache commons-collections library permitted code
execution when deserializing objects involving a specially constructed
chain of classes. A remote attacker could use this flaw to execute
arbitrary code with the permissions of the application using the
commons-collections library. (CVE-2015-7501)

With this update, deserialization of certain classes in the
commons-collections library is no longer allowed. Applications that require
those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to re-enable
their deserialization.

Further information about this security flaw may be found at the linked references.

All users of jakarta-commons-collections are advised to upgrade to these
updated packages, which contain a backported patch to correct this issue.
All running applications using the commons-collections library must be
restarted for the update to take effect.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

For details on how to apply this update, refer to the linked KB article.

5. Bugs fixed:

1279330 - CVE-2015-7501 apache-commons-collections: InvokerTransformer code execution during deserialisation

6. Package List:

Red Hat Enterprise Linux Desktop Optional (v. 6):

Source:
jakarta-commons-collections-3.2.1-3.5.el6_7.src.rpm

noarch:
jakarta-commons-collections-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-javadoc-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-testframework-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-testframework-javadoc-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-tomcat5-3.2.1-3.5.el6_7.noarch.rpm

Red Hat Enterprise Linux HPC Node Optional (v. 6):

Source:
jakarta-commons-collections-3.2.1-3.5.el6_7.src.rpm

noarch:
jakarta-commons-collections-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-javadoc-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-testframework-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-testframework-javadoc-3.2.1-3.5.el6_7.noarch.rpm
jakarta-commons-collections-tomcat5-3.2.1-3.5. ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"jakarta-commons-collections on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-December/021512.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections", rpm:"jakarta-commons-collections~3.2.1~3.5.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-javadoc", rpm:"jakarta-commons-collections-javadoc~3.2.1~3.5.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-testframework", rpm:"jakarta-commons-collections-testframework~3.2.1~3.5.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-testframework-javadoc", rpm:"jakarta-commons-collections-testframework-javadoc~3.2.1~3.5.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-collections-tomcat5", rpm:"jakarta-commons-collections-tomcat5~3.2.1~3.5.el6_7", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
