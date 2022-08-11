###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for 389-ds-base RHSA-2016:2765-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871716");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-11-16 05:07:02 +0100 (Wed, 16 Nov 2016)");
  script_cve_id("CVE-2016-4992", "CVE-2016-5405", "CVE-2016-5416");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for 389-ds-base RHSA-2016:2765-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3 (LDAPv3) compliant server. The
base packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

Security Fix(es):

  * It was found that 389 Directory Server was vulnerable to a flaw in which
the default ACI (Access Control Instructions) could be read by an anonymous
user. This could lead to leakage of sensitive information. (CVE-2016-5416)

  * An information disclosure flaw was found in 389 Directory Server. A user
with no access to objects in certain LDAP sub-tree could send LDAP ADD
operations with a specific object name. The error message returned to the
user was different based on whether the target object existed or not.
(CVE-2016-4992)

  * It was found that 389 Directory Server was vulnerable to a remote
password disclosure via timing attack. A remote attacker could possibly use
this flaw to retrieve directory server password after many tries.
(CVE-2016-5405)

The CVE-2016-5416 issue was discovered by Viktor Ashirov (Red Hat)  the
CVE-2016-4992 issue was discovered by Petr Spacek (Red Hat) and Martin
Basti (Red Hat)  and the CVE-2016-5405 issue was discovered by William
Brown (Red Hat).

Bug Fix(es):

  * Previously, a bug in the changelog iterator buffer caused it to point to
an incorrect position when reloading the buffer. This caused replication to
skip parts of the changelog, and consequently some changes were not
replicated. This bug has been fixed, and replication data loss due to an
incorrectly reloaded changelog buffer no longer occurs. (BZ#1354331)

  * Previously, if internal modifications were generated on a consumer (for
example by the Account Policy plug-in) and additional changes to the same
attributes were received from replication, a bug caused Directory Server to
accumulate state information on the consumer. The bug has been fixed by
making sure that replace operations are only applied if they are newer than
existing attribute deletion change sequence numbers (CSNs), and state
information no longer accumulates in this situation. (BZ#1379599)

Enhancement(s):

  * In a multi-master replication environment where multiple masters receive
updates at the same time, it was previously possible for a single master to
obtain exclusive access to a replica and hold it for a very long time due
to problems such as a slow network connection. During this time, other
masters were blocked from accessing the same replica, which considerably
slowed down the replication process. This update adds a new configuration ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"389-ds-base on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2016-November/msg00071.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.2.11.15~84.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~1.2.11.15~84.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.2.11.15~84.el6_8", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
