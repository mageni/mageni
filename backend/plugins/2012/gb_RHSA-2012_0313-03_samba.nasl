###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for samba RHSA-2012:0313-03
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
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2012-February/msg00042.html");
  script_oid("1.3.6.1.4.1.25623.1.0.870551");
  script_version("$Revision: 14114 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-12 12:48:52 +0100 (Tue, 12 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-02-21 18:56:40 +0530 (Tue, 21 Feb 2012)");
  script_cve_id("CVE-2010-0926");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_name("RedHat Update for samba RHSA-2012:0313-03");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'samba'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_5");
  script_tag(name:"affected", value:"samba on Red Hat Enterprise Linux (v. 5 server)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_tag(name:"insight", value:"Samba is an open-source implementation of the Server Message Block (SMB) or
  Common Internet File System (CIFS) protocol, which allows PC-compatible
  machines to share files, printers, and other information.

  The default Samba server configuration enabled both the 'wide links' and
  'unix extensions' options, allowing Samba clients with write access to a
  share to create symbolic links that point to any location on the file
  system. Clients connecting with CIFS UNIX extensions disabled could have
  such links resolved on the server, allowing them to access and possibly
  overwrite files outside of the share. With this update, 'wide links' is
  set to 'no' by default. In addition, the update ensures 'wide links' is
  disabled for shares that have 'unix extensions' enabled. (CVE-2010-0926)

  Warning: This update may cause files and directories that are only linked
  to Samba shares using symbolic links to become inaccessible to Samba
  clients. In deployments where support for CIFS UNIX extensions is not
  needed (such as when files are exported to Microsoft Windows clients),
  administrators may prefer to set the 'unix extensions' option to 'no' to
  allow the use of symbolic links to access files out of the shared
  directories. All existing symbolic links in a share should be reviewed
  before re-enabling 'wide links'.

  These updated samba packages also fix the following bug:

  * The smbclient tool sometimes failed to return the proper exit status
  code. Consequently, using smbclient in a script caused some scripts to
  fail. With this update, an upstream patch has been applied and smbclient
  now returns the correct exit status. (BZ#768908)

  In addition, these updated samba packages provide the following
  enhancement:

  * With this update, support for Windows Server 2008 R2 domains has been
  added. (BZ#736124)

  Users are advised to upgrade to these updated samba packages, which correct
  these issues and add this enhancement. After installing this update, the
  smb service will be restarted automatically.");
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

  if ((res = isrpmvuln(pkg:"libsmbclient", rpm:"libsmbclient~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libsmbclient-devel", rpm:"libsmbclient-devel~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-debuginfo", rpm:"samba-debuginfo~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.33~3.37.el5", rls:"RHENT_5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
