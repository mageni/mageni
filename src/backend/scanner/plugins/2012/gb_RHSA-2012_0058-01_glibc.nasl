###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for glibc RHSA-2012:0058-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-January/msg00020.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870722");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:53:27 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2009-5029", "CVE-2011-4609");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for glibc RHSA-2012:0058-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'glibc'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"glibc on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The glibc packages contain the standard C libraries used by multiple
  programs on the system. These packages contain the standard C and the
  standard math libraries. Without these two libraries, a Linux system cannot
  function properly.

  An integer overflow flaw, leading to a heap-based buffer overflow, was
  found in the way the glibc library read timezone files. If a
  carefully-crafted timezone file was loaded by an application linked against
  glibc, it could cause the application to crash or, potentially, execute
  arbitrary code with the privileges of the user running the application.
  (CVE-2009-5029)

  A denial of service flaw was found in the remote procedure call (RPC)
  implementation in glibc. A remote attacker able to open a large number of
  connections to an RPC service that is using the RPC implementation from
  glibc, could use this flaw to make that service use an excessive amount of
  CPU time. (CVE-2011-4609)

  This update also fixes the following bugs:

  * glibc had incorrect information for numeric separators and groupings for
  specific French, Spanish, and German locales. Therefore, applications
  utilizing glibc's locale support printed numbers with the wrong separators
  and groupings when those locales were in use. With this update, the
  separator and grouping information has been fixed. (BZ#754116)

  * The RHBA-2011:1179 glibc update introduced a regression, causing glibc to
  incorrectly parse groups with more than 126 members, resulting in
  applications such as 'id' failing to list all the groups a particular user
  was a member of. With this update, group parsing has been fixed.
  (BZ#766484)

  * glibc incorrectly allocated too much memory due to a race condition
  within its own malloc routines. This could cause a multi-threaded
  application to allocate more memory than was expected. With this update,
  the race condition has been fixed, and malloc's behavior is now consistent
  with the documentation regarding the MALLOC_ARENA_TEST and MALLOC_ARENA_MAX
  environment variables. (BZ#769594)

  Users should upgrade to these updated packages, which contain backported
  patches to resolve these issues.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"glibc", rpm:"glibc~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-common", rpm:"glibc-common~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo", rpm:"glibc-debuginfo~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-debuginfo-common", rpm:"glibc-debuginfo-common~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-devel", rpm:"glibc-devel~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-headers", rpm:"glibc-headers~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"glibc-utils", rpm:"glibc-utils~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nscd", rpm:"nscd~2.12~1.47.el6_2.5", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
