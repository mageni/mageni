###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for mingw32-libxml2 CESA-2013:0217 centos6
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-February/019221.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881592");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-02-04 09:55:24 +0530 (Mon, 04 Feb 2013)");
  script_cve_id("CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0216", "CVE-2011-1944",
                "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3102", "CVE-2011-3905",
                "CVE-2011-3919", "CVE-2012-0841", "CVE-2012-5134");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("CentOS Update for mingw32-libxml2 CESA-2013:0217 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mingw32-libxml2'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"mingw32-libxml2 on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"These packages provide the libxml2 library, a development toolbox providing
  the implementation of various XML standards, for users of MinGW (Minimalist
  GNU for Windows).

  IMPORTANT NOTE: The mingw32 packages in Red Hat Enterprise Linux 6 will no
  longer be updated proactively and will be deprecated with the release of
  Red Hat Enterprise Linux 6.4. These packages were provided to support other
  capabilities in Red Hat Enterprise Linux and were not intended for direct
  customer use. Customers are advised to not use these packages with
  immediate effect. Future updates to these packages will be at Red Hat's
  discretion and these packages may be removed in a future minor release.

  A heap-based buffer overflow flaw was found in the way libxml2 decoded
  entity references with long names. A remote attacker could provide a
  specially-crafted XML file that, when opened in an application linked
  against libxml2, would cause the application to crash or, potentially,
  execute arbitrary code with the privileges of the user running the
  application. (CVE-2011-3919)

  A heap-based buffer underflow flaw was found in the way libxml2 decoded
  certain entities. A remote attacker could provide a specially-crafted XML
  file that, when opened in an application linked against libxml2, would
  cause the application to crash or, potentially, execute arbitrary code with
  the privileges of the user running the application. (CVE-2012-5134)

  It was found that the hashing routine used by libxml2 arrays was
  susceptible to predictable hash collisions. Sending a specially-crafted
  message to an XML service could result in longer processing time, which
  could lead to a denial of service. To mitigate this issue, randomization
  has been added to the hashing function to reduce the chance of an attacker
  successfully causing intentional collisions. (CVE-2012-0841)

  Multiple flaws were found in the way libxml2 parsed certain XPath (XML Path
  Language) expressions. If an attacker were able to supply a
  specially-crafted XML file to an application using libxml2, as well as an
  XPath expression for that application to run against the crafted file, it
  could cause the application to crash. (CVE-2010-4008, CVE-2010-4494,
  CVE-2011-2821, CVE-2011-2834)

  Two heap-based buffer overflow flaws were found in the way libxml2 decoded
  certain XML files. A remote attacker could provide a specially-crafted XML
  file that, when opened in an application linked against libxml2, would
  cause the application to crash or, potentially, execute arbitrary code with
  the privileges of the user ...

  Description truncated, please see the referenced URL(s) for more information.");
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

  if ((res = isrpmvuln(pkg:"mingw32-libxml2", rpm:"mingw32-libxml2~2.7.6~6.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mingw32-libxml2-static", rpm:"mingw32-libxml2-static~2.7.6~6.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
