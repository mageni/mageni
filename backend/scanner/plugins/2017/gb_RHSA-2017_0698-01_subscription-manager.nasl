###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for subscription-manager RHSA-2017:0698-01
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.871785");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-03-22 05:48:42 +0100 (Wed, 22 Mar 2017)");
  script_cve_id("CVE-2016-4455");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for subscription-manager RHSA-2017:0698-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'subscription-manager'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The subscription-manager packages provide
programs and libraries to allow users to manage subscriptions and yum repositories
from the Red Hat entitlement platform.

The subscription-manager-migration-data package provides certificates for
migrating a system from the legacy Red Hat Network Classic (RHN) to Red Hat
Subscription Management (RHSM).

The python-rhsm packages provide a library for communicating with the
representational state transfer (REST) interface of a Red Hat Unified
Entitlement Platform. The Subscription Management tools use this interface
to manage system entitlements, certificates, and access to content.

The following packages have been upgraded to a later upstream version:
subscription-manager (1.18.10), python-rhsm (1.18.6),
subscription-manager-migration-data (2.0.34). (BZ#1383475, BZ#1385446,
BZ#1385382)

Security Fix(es):

  * It was found that subscription-manager set weak permissions on files in
/var/lib/rhsm/, causing an information disclosure. A local, unprivileged
user could use this flaw to access sensitive data that could potentially be
used in a social engineering attack. (CVE-2016-4455)

Red Hat would like to thank Robert Scheck for reporting this issue.

Additional Changes:

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section.");
  script_tag(name:"affected", value:"subscription-manager on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-March/msg00051.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"python-rhsm", rpm:"python-rhsm~1.18.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rhsm-certificates", rpm:"python-rhsm-certificates~1.18.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-rhsm-debuginfo", rpm:"python-rhsm-debuginfo~1.18.6~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager", rpm:"subscription-manager~1.18.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-debuginfo", rpm:"subscription-manager-debuginfo~1.18.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-firstboot", rpm:"subscription-manager-firstboot~1.18.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-gui", rpm:"subscription-manager-gui~1.18.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-migration", rpm:"subscription-manager-migration~1.18.10~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"subscription-manager-migration-data", rpm:"subscription-manager-migration-data~2.0.34~1.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
