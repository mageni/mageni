###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for cifs-utils CESA-2012:0902 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-July/018721.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881178");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-07-30 16:33:57 +0530 (Mon, 30 Jul 2012)");
  script_cve_id("CVE-2012-1586");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_name("CentOS Update for cifs-utils CESA-2012:0902 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cifs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"cifs-utils on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  * The cifs.upcall utility previously always used the '/etc/krb5.conf' file
  regardless of whether the user had specified a custom K ...

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

  if ((res = isrpmvuln(pkg:"cifs-utils", rpm:"cifs-utils~4.8.1~10.el6", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
