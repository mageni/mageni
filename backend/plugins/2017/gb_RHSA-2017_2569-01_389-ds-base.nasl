###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_RHSA-2017_2569-01_389-ds-base.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# RedHat Update for 389-ds-base RHSA-2017:2569-01
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
  script_oid("1.3.6.1.4.1.25623.1.0.811767");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-09-06 07:17:07 +0200 (Wed, 06 Sep 2017)");
  script_cve_id("CVE-2017-7551");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for 389-ds-base RHSA-2017:2569-01");
  script_tag(name:"summary", value:"The remote host is missing an update for the '389-ds-base'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"389 Directory Server is an LDAP version 3
(LDAPv3) compliant server. The base packages include the Lightweight Directory
Access Protocol (LDAP) server and command-line utilities for server administration.

Security Fix(es):

  * A flaw was found in the way 389-ds-base handled authentication attempts
against locked accounts. A remote attacker could potentially use this flaw
to continue password brute-forcing attacks against LDAP accounts, thereby
bypassing the protection offered by the directory server's password lockout
policy. (CVE-2017-7551)

Bug Fix(es):

  * In a multi-replication environments, if operations in one back end
triggered updates in another back end, the Replica Update Vector (RUV) of
the back end was incorrect and replication failed. This fix enables
Directory Server to handle Change Sequence Number (CSN) pending lists
across multiple back ends. As a result, replication works correctly.
(BZ#1476161)

  * Due to a low default entry cache size value, the Directory Server
database had to resolve many deadlocks during resource-intensive tasks. In
certain situations, this could result in a 'DB PANIC' error and the server
no longer responded to requests. After the server was restarted, Directory
Server started with a delay to recover the database. However, this recovery
could fail, and the database could corrupt. This patch increases the
default entry cache size in the nsslapd-cachememsize parameter to 200 MB.
As a result, out-of-lock situations or 'DB PANIC' errors no longer occur in
the mentioned scenario. (BZ#1476162)

  * Previously, if replication was enabled and a changelog file existed,
performing a backup on this master server failed. This update sets the
internal options for correctly copying a file. As a result, creating a
backup now succeeds in the mentioned scenario. (BZ#1479755)

  * In certain situations, if the server was previously abruptly shut down,
the /etc/dirsrv/ instance_name /dse.ldif configuration file became
corrupted. As a consequence, Directory Server failed to start. With this
patch, the server now calls the fsync() function before shutting down to
force the file system to write any changes to the disk. As a result, the
configuration no longer becomes corrupted, regardless how the server gets
stopped. (BZ#1479757)");
  script_tag(name:"affected", value:"389-ds-base on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2017-September/msg00001.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"389-ds-base", rpm:"389-ds-base~1.3.6.1~19.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-debuginfo", rpm:"389-ds-base-debuginfo~1.3.6.1~19.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"389-ds-base-libs", rpm:"389-ds-base-libs~1.3.6.1~19.el7_4", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
