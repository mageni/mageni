###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for samba CESA-2009:1529 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-October/016276.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880727");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1888", "CVE-2009-2813", "CVE-2009-2906", "CVE-2009-2948");
  script_name("CentOS Update for samba CESA-2009:1529 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"samba on CentOS 5");
  script_tag(name:"insight", value:"Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A denial of service flaw was found in the Samba smbd daemon. An
  authenticated, remote user could send a specially-crafted response that
  would cause an smbd child process to enter an infinite loop. An
  authenticated, remote user could use this flaw to exhaust system resources
  by opening multiple CIFS sessions. (CVE-2009-2906)

  An uninitialized data access flaw was discovered in the smbd daemon when
  using the non-default 'dos filemode' configuration option in 'smb.conf'. An
  authenticated, remote user with write access to a file could possibly use
  this flaw to change an access control list for that file, even when such
  access should have been denied. (CVE-2009-1888)

  A flaw was discovered in the way Samba handled users without a home
  directory set in the back-end password database (e.g. '/etc/passwd'). If a
  share for the home directory of such a user was created (e.g. using the
  automated '[homes]' share), any user able to access that share could see
  the whole file system, possibly bypassing intended access restrictions.
  (CVE-2009-2813)

  The mount.cifs program printed CIFS passwords as part of its debug output
  when running in verbose mode. When mount.cifs had the setuid bit set, a
  local, unprivileged user could use this flaw to disclose passwords from a
  file that would otherwise be inaccessible to that user. Note: mount.cifs
  from the samba packages distributed by Red Hat does not have the setuid bit
  set. This flaw only affected systems where the setuid bit was manually set
  by an administrator. (CVE-2009-2948)

  Users of Samba should upgrade to these updated packages, which contain
  backported patches to correct these issues. After installing this update,
  the smb service will be restarted automatically.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.33~3.15.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.33~3.15.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.33~3.15.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.33~3.15.el5_4", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
