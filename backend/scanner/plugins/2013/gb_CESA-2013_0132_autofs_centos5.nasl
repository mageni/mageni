###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for autofs CESA-2013:0132 centos5
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-January/019169.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881558");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:38:00 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2012-2697");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_name("CentOS Update for autofs CESA-2013:0132 centos5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'autofs'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"autofs on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  * A function to check the validity of a mount location was meant to check
  only for a small subset of map location errors. A recent modification in
  error reporting inverted a logic test in this validating function.
  Consequently, the scope of the test was widened, which caused the automount
  daemon to report false positive failures. With this update, the faulty
  logic test has been corrected and false positive failures no longer occur.
  (BZ#798448)

  * When there were many attempts to access invalid or non-existent keys, the
  automount daemon used excessive CPU resources. As a consequence, systems
  sometimes became unresponsive. The code has been improved so that automount
  checks for invalid keys earlier in the process which has eliminated a
  significant amount of the processing overhead. (BZ#847101)

  * The auto.master(5) man page did not document the 't, --timeout' option
  in the FORMAT options section. This update adds this information to the man
  page. (BZ#859890)

  This update also adds the following enhancement:

  * Previously, it was not possible to configure separate timeout values for
  individual direct map entries in the autofs master map. This update adds
  this functionality. (BZ#690404)

  All users of autofs are advised to upgrade to this updated package, which
  contains backported patches to correct these issues and add this
  enhancement.");
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

  if ((res = isrpmvuln(pkg:"autofs", rpm:"autofs~5.0.1~0.rc2.177.el5", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
