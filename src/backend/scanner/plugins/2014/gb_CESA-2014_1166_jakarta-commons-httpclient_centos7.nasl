###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for jakarta-commons-httpclient CESA-2014:1166 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882010");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-09-10 06:20:19 +0200 (Wed, 10 Sep 2014)");
  script_cve_id("CVE-2014-3577", "CVE-2012-6153");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_name("CentOS Update for jakarta-commons-httpclient CESA-2014:1166 centos7");
  script_tag(name:"insight", value:"Jakarta Commons HTTPClient implements the
client side of HTTP standards.

It was discovered that the HTTPClient incorrectly extracted host name from
an X.509 certificate subject's Common Name (CN) field. A man-in-the-middle
attacker could use this flaw to spoof an SSL server using a specially
crafted X.509 certificate. (CVE-2014-3577)

For additional information on this flaw, refer to the Knowledgebase
article in the References section.

All jakarta-commons-httpclient users are advised to upgrade to these
updated packages, which contain a backported patch to correct this issue.

4. Solution:

Before applying this update, make sure all previously released errata
relevant to your system have been applied.

This update is available via the Red Hat Network. Details on how to use the
Red Hat Network to apply this update are available at the linked references.

5. Bugs fixed:

1129074 - CVE-2014-3577 Apache HttpComponents client: SSL hostname verification
bypass, incomplete CVE-2012-6153 fix

6. Package List:

Red Hat Enterprise Linux Desktop (v. 5 client):

Source:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.src.rpm

i386:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.i386.rpm

x86_64:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.x86_64.rpm

Red Hat Enterprise Linux Desktop Workstation (v. 5 client):

Source:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.src.rpm

i386:
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-demo-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-javadoc-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-manual-3.0-7jpp.4.el5_10.i386.rpm

x86_64:
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-demo-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-javadoc-3.0-7jpp.4.el5_10.x86_64.rpm
jakarta-commons-httpclient-manual-3.0-7jpp.4.el5_10.x86_64.rpm

Red Hat Enterprise Linux (v. 5 server):

Source:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.src.rpm

i386:
jakarta-commons-httpclient-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-debuginfo-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-demo-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-javadoc-3.0-7jpp.4.el5_10.i386.rpm
jakarta-commons-httpclient-manual-3.0-7jpp.4.el5_10.i386.rpm

ia64:
jak ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"jakarta-commons-httpclient on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020546.html");
  script_xref(name:"URL", value:"https://access.redhat.com/articles/11258");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'jakarta-commons-httpclient'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient", rpm:"jakarta-commons-httpclient~3.1~16.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-demo", rpm:"jakarta-commons-httpclient-demo~3.1~16.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-javadoc", rpm:"jakarta-commons-httpclient-javadoc~3.1~16.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"jakarta-commons-httpclient-manual", rpm:"jakarta-commons-httpclient-manual~3.1~16.el7_0", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
