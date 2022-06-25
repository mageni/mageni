###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for cifs-utils RHSA-2012:0902-04
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-June/msg00035.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870774");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-06-22 10:26:27 +0530 (Fri, 22 Jun 2012)");
  script_cve_id("CVE-2012-1586");
  script_name("RedHat Update for cifs-utils RHSA-2012:0902-04");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"cifs-utils on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The cifs-utils package contains tools for mounting and managing shares on
  Linux using the SMB/CIFS protocol. The CIFS shares can be used as standard
  Linux file systems.

  A file existence disclosure flaw was found in mount.cifs. If the tool was
  installed with the setuid bit set, a local attacker could use this flaw to
  determine the existence of files or directories in directories not
  accessible to the attacker. (CVE-2012-1586)

  Note: mount.cifs from the cifs-utils package distributed by Red Hat does
  not have the setuid bit set. We recommend that administrators do not
  manually set the setuid bit for mount.cifs.

  This update also fixes the following bugs:

  * The cifs.mount(8) manual page was previously missing documentation for
  several mount options. With this update, the missing entries have been
  added to the manual page. (BZ#769923)

  * Previously, the mount.cifs utility did not properly update the
  '/etc/mtab' system information file when remounting an existing CIFS
  mount. Consequently, mount.cifs created a duplicate entry of the existing
  mount entry. This update adds the del_mtab() function to cifs.mount, which
  ensures that the old mount entry is removed from '/etc/mtab' before adding
  the updated mount entry. (BZ#770004)

  * The mount.cifs utility did not properly convert user and group names to
  numeric UIDs and GIDs. Therefore, when the 'uid', 'gid' or 'cruid' mount
  options were specified with user or group names, CIFS shares were mounted
  with default values. This caused shares to be inaccessible to the intended
  users because UID and GID is set to '0' by default. With this update, user
  and group names are properly converted so that CIFS shares are now mounted
  with specified user and group ownership as expected. (BZ#796463)

  * The cifs.upcall utility did not respect the 'domain_realm' section in
  the 'krb5.conf' file and worked only with the default domain.
  Consequently, an attempt to mount a CIFS share from a different than the
  default domain failed with the following error message:

      mount error(126): Required key not available

  This update modifies the underlying code so that cifs.upcall handles
  multiple Kerberos domains correctly and CIFS shares can now be mounted as
  expected in a multi-domain environment. (BZ#805490)

  In addition, this update adds the following enhancements:

  * The cifs.upcall util ...

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

if(release == "RHENT_6")
{

  if ((res = isrpmvuln(pkg:"cifs-utils", rpm:"cifs-utils~4.8.1~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"cifs-utils-debuginfo", rpm:"cifs-utils-debuginfo~4.8.1~10.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
