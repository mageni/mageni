###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for icedtea-web RHSA-2011:1100-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.870699");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-06-06 10:50:25 +0530 (Wed, 06 Jun 2012)");
  script_cve_id("CVE-2011-2513", "CVE-2011-2514");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for icedtea-web RHSA-2011:1100-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icedtea-web'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"icedtea-web on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The IcedTea-Web project provides a Java web browser plug-in and an
  implementation of Java Web Start, which is based on the Netx project. It
  also contains a configuration tool for managing deployment settings for the
  plug-in and Web Start implementations.

  A flaw was discovered in the JNLP (Java Network Launching Protocol)
  implementation in IcedTea-Web. An unsigned Java Web Start application
  could use this flaw to manipulate the content of a Security Warning
  dialog box, to trick a user into granting the application unintended access
  permissions to local files. (CVE-2011-2514)

  An information disclosure flaw was discovered in the JNLP implementation in
  IcedTea-Web. An unsigned Java Web Start application or Java applet could
  use this flaw to determine the path to the cache directory used to store
  downloaded Java class and archive files, and therefore determine the user's
  login name. (CVE-2011-2513)

  All icedtea-web users should upgrade to these updated packages, which
  contain backported patches to correct these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-July/msg00032.html");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"icedtea-web", rpm:"icedtea-web~1.0.4~2.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"icedtea-web-debuginfo", rpm:"icedtea-web-debuginfo~1.0.4~2.el6_1", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
