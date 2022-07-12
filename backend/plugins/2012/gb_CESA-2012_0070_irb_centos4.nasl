###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for irb CESA-2012:0070 centos4
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-January/018401.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881191");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:39:50 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2011-3009", "CVE-2011-4815", "CVE-2011-2686", "CVE-2011-2705");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for irb CESA-2012:0070 centos4");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'irb'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS4");
  script_tag(name:"affected", value:"irb on CentOS 4");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"Ruby is an extensible, interpreted, object-oriented, scripting language. It
  has features to process text files and to do system management tasks.

  A denial of service flaw was found in the implementation of associative
  arrays (hashes) in Ruby. An attacker able to supply a large number of
  inputs to a Ruby application (such as HTTP POST request parameters sent to
  a web application) that are used as keys when inserting data into an array
  could trigger multiple hash function collisions, making array operations
  take an excessive amount of CPU time. To mitigate this issue, randomization
  has been added to the hash function to reduce the chance of an attacker
  successfully causing intentional collisions. (CVE-2011-4815)

  It was found that Ruby did not reinitialize the PRNG (pseudorandom number
  generator) after forking a child process. This could eventually lead to the
  PRNG returning the same result twice. An attacker keeping track of the
  values returned by one child process could use this flaw to predict the
  values the PRNG would return in other child processes (as long as the
  parent process persisted). (CVE-2011-3009)

  Red Hat would like to thank oCERT for reporting CVE-2011-4815. oCERT
  acknowledges Julian Wälde and Alexander Klink as the original reporters of
  CVE-2011-4815.

  All users of ruby are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues.");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"irb", rpm:"irb~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby", rpm:"ruby~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-devel", rpm:"ruby-devel~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-docs", rpm:"ruby-docs~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-libs", rpm:"ruby-libs~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-mode", rpm:"ruby-mode~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ruby-tcltk", rpm:"ruby-tcltk~1.8.1~18.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
