###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for autofs RHSA-2013:0132-01
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2013-January/msg00015.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870886");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2013-01-11 16:42:44 +0530 (Fri, 11 Jan 2013)");
  script_cve_id("CVE-2012-2697");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_name("RedHat Update for autofs RHSA-2013:0132-01");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"autofs on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The autofs utility controls the operation of the automount daemon. The
  automount daemon automatically mounts and unmounts file systems.

  A bug fix included in RHBA-2012:0264 introduced a denial of service flaw in
  autofs. When using autofs with LDAP, a local user could use this flaw to
  crash autofs, preventing future mount requests from being processed until
  the autofs service was restarted. Note: This flaw did not impact existing
  mounts (except for preventing mount expiration). (CVE-2012-2697)

  Red Hat would like to thank Ray Rocker for reporting this issue.

  This update also fixes the following bugs:

  * The autofs init script sometimes timed out waiting for the automount
  daemon to exit and returned a shutdown failure if the daemon failed to exit
  in time. To resolve this problem, the amount of time that the init script
  waits for the daemon has been increased to allow for cases where servers
  are slow to respond or there are many active mounts. (BZ#585058)

  * Due to an omission when backporting a change, autofs attempted to
  download the entire LDAP map at startup. This mistake has now been
  corrected. (BZ#767428)

  All users of autofs are advised to upgrade to this updated package, which
  contains backported patches to correct these issues and add this
  enhancement.

   Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_5")
{

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.1~0.rc2.177.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"autofs-debuginfo", rpm:"autofs-debuginfo~5.0.1~0.rc2.177.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
