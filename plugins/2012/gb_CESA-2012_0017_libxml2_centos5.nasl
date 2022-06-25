###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for libxml2 CESA-2012:0017 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-January/018371.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881182");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:34:13 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2010-4008", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2834",
                "CVE-2011-3905", "CVE-2011-3919");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for libxml2 CESA-2012:0017 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"libxml2 on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The libxml2 library is a development toolbox providing the implementation
  of various XML standards. One of those standards is the XML Path Language
  (XPath), which is a language for addressing parts of an XML document.

  A heap-based buffer overflow flaw was found in the way libxml2 decoded
  entity references with long names. A remote attacker could provide a
  specially-crafted XML file that, when opened in an application linked
  against libxml2, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-3919)

  An off-by-one error, leading to a heap-based buffer overflow, was found in
  the way libxml2 parsed certain XML files. A remote attacker could provide a
  specially-crafted XML file that, when opened in an application linked
  against libxml2, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-0216)

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way libxml2 parsed certain XPath expressions. If an attacker
  were able to supply a specially-crafted XML file to an application using
  libxml2, as well as an XPath expression for that application to run against
  the crafted file, it could cause the application to crash or, possibly,
  execute arbitrary code. (CVE-2011-1944)

  Flaws were found in the way libxml2 parsed certain XPath expressions. If an
  attacker were able to supply a specially-crafted XML file to an application
  using libxml2, as well as an XPath expression for that application to run
  against the crafted file, it could cause the application to crash.
  (CVE-2010-4008, CVE-2011-2834)

  An out-of-bounds memory read flaw was found in libxml2. A remote attacker
  could provide a specially-crafted XML file that, when opened in an
  application linked against libxml2, would cause the application to crash.
  (CVE-2011-3905)

  Note: Red Hat does not ship any applications that use libxml2 in a way that
  would allow the CVE-2011-1944, CVE-2010-4008, and CVE-2011-2834 flaws to be
  exploited. However, third-party applications may allow XPath expressions to
  be passed which could trigger these flaws.

  Red Hat would like to thank the Google Security Team for reporting the
  CVE-2010-4008 issue. Upstream acknowledges Bui Quang Minh from Bkis as the
  original reporter of CVE-2010-4008.

  All users of libxml2 are advised to upgrade to these updated packages,
  which contain backported patches to correct these issues. The desktop must
  be restarted (log out, then log back in) for this update to take effect.");
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

  if ((res = isrpmvuln(pkg:"libxml2", rpm:"libxml2~2.6.26~2.1.12.el5_7.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-devel", rpm:"libxml2-devel~2.6.26~2.1.12.el5_7.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxml2-python", rpm:"libxml2-python~2.6.26~2.1.12.el5_7.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
