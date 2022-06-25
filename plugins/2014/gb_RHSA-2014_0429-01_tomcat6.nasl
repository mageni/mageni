###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for tomcat6 RHSA-2014:0429-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.871159");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2014-05-02 10:15:43 +0530 (Fri, 02 May 2014)");
  script_cve_id("CVE-2013-4286", "CVE-2013-4322", "CVE-2014-0050", "CVE-2012-3544");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for tomcat6 RHSA-2014:0429-01");


  script_tag(name:"affected", value:"tomcat6 on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"insight", value:"Apache Tomcat is a servlet container for the Java Servlet and JavaServer
Pages (JSP) technologies.

It was found that when Tomcat processed a series of HTTP requests in which
at least one request contained either multiple content-length headers, or
one content-length header with a chunked transfer-encoding header, Tomcat
would incorrectly handle the request. A remote attacker could use this flaw
to poison a web cache, perform cross-site scripting (XSS) attacks, or
obtain sensitive information from other requests. (CVE-2013-4286)

It was discovered that the fix for CVE-2012-3544 did not properly resolve a
denial of service flaw in the way Tomcat processed chunk extensions and
trailing headers in chunked requests. A remote attacker could use this flaw
to send an excessively long request that, when processed by Tomcat, could
consume network bandwidth, CPU, and memory on the Tomcat server. Note that
chunked transfer encoding is enabled by default. (CVE-2013-4322)

A denial of service flaw was found in the way Apache Commons FileUpload
handled small-sized buffers used by MultipartStream. A remote attacker
could use this flaw to create a malformed Content-Type header for a
multipart request, causing JBoss Web to enter an infinite loop when
processing such an incoming request. (CVE-2014-0050)

All Tomcat users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. Tomcat must be
restarted for this update to take effect.");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2014-April/msg00041.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat6'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"tomcat6", rpm:"tomcat6~6.0.24~64.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-el", rpm:"tomcat6-el~2.1~api~6.0.24~64.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-jsp", rpm:"tomcat6-jsp~2.1~api~6.0.24~64.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-lib", rpm:"tomcat6-lib~6.0.24~64.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"tomcat6-servlet", rpm:"tomcat6-servlet~2.5~api~6.0.24~64.el6_5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
