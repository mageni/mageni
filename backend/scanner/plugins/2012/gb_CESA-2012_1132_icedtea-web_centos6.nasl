###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for icedtea-web CESA-2012:1132 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018778.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881466");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-08-03 11:17:19 +0530 (Fri, 03 Aug 2012)");
  script_cve_id("CVE-2012-3422", "CVE-2012-3423");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for icedtea-web CESA-2012:1132 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"icedtea-web on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The IcedTea-Web project provides a Java web browser plug-in and an
  implementation of Java Web Start, which is based on the Netx project. It
  also contains a configuration tool for managing deployment settings for the
  plug-in and Web Start implementations.

  An uninitialized pointer use flaw was found in the IcedTea-Web plug-in.
  Visiting a malicious web page could possibly cause a web browser using the
  IcedTea-Web plug-in to crash, disclose a portion of its memory, or execute
  arbitrary code. (CVE-2012-3422)

  It was discovered that the IcedTea-Web plug-in incorrectly assumed all
  strings received from the browser were NUL terminated. When using the
  plug-in with a web browser that does not NUL terminate strings, visiting a
  web page containing a Java applet could possibly cause the browser to
  crash, disclose a portion of its memory, or execute arbitrary code.
  (CVE-2012-3423)

  Red Hat would like to thank Chamal De Silva for reporting the CVE-2012-3422
  issue.

  This erratum also upgrades IcedTea-Web to version 1.2.1. Refer to the NEWS
  file, linked to in the References, for further information.

  All IcedTea-Web users should upgrade to these updated packages, which
  resolve these issues. Web browsers using the IcedTea-Web browser plug-in
  must be restarted for this update to take effect.");
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

if(release == "CentOS6")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.2.1~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-javadoc", rpm:"icedtea-web-javadoc~1.2.1~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
