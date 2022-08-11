###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for nfs-utils RHSA-2011:1534-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2011-December/msg00009.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870655");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 10:44:04 +0530 (Mon, 09 Jul 2012)");
  script_cve_id("CVE-2011-1749", "CVE-2011-2500");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("RedHat Update for nfs-utils RHSA-2011:1534-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_6");
  script_tag(name:"affected", value:"nfs-utils on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"The nfs-utils packages provide a daemon for the kernel Network File System
  (NFS) server, and related tools such as the mount.nfs, umount.nfs, and
  showmount programs.

  A flaw was found in the way nfs-utils performed IP based authentication of
  mount requests. In configurations where a directory was exported to a group
  of systems using a DNS wildcard or NIS (Network Information Service)
  netgroup, an attacker could possibly gain access to other directories
  exported to a specific host or subnet, bypassing intended access
  restrictions. (CVE-2011-2500)

  It was found that the mount.nfs tool did not handle certain errors
  correctly when updating the mtab (mounted file systems table) file. A local
  attacker could use this flaw to corrupt the mtab file. (CVE-2011-1749)

  This update also fixes several bugs and adds an enhancement. Documentation
  for these bug fixes and the enhancement will be available shortly from the
  Technical Notes document, linked to in the References section.

  Users of nfs-utils are advised to upgrade to these updated packages, which
  contain backported patches to resolve these issues and add this
  enhancement. After installing this update, the nfs service will be
  restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"nfs-utils", rpm:"nfs-utils~1.2.3~15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nfs-utils-debuginfo", rpm:"nfs-utils-debuginfo~1.2.3~15.el6", rls:"RHENT_6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
