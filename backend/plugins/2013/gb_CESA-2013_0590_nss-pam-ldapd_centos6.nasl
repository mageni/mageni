###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for nss-pam-ldapd CESA-2013:0590 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2013-March/019628.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881638");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2013-03-12 09:59:07 +0530 (Tue, 12 Mar 2013)");
  script_cve_id("CVE-2013-0288");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for nss-pam-ldapd CESA-2013:0590 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nss-pam-ldapd'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"nss-pam-ldapd on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"The nss-pam-ldapd packages provide the nss-pam-ldapd daemon (nslcd), which
  uses a directory server to lookup name service information on behalf of a
  lightweight nsswitch module.

  An array index error, leading to a stack-based buffer overflow flaw, was
  found in the way nss-pam-ldapd managed open file descriptors. An attacker
  able to make a process have a large number of open file descriptors and
  perform name lookups could use this flaw to cause the process to crash or,
  potentially, execute arbitrary code with the privileges of the user running
  the process. (CVE-2013-0288)

  Red Hat would like to thank Garth Mollett for reporting this issue.

  All users of nss-pam-ldapd are advised to upgrade to these updated
  packages, which contain a backported patch to fix this issue.");
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

  if ((res = isrpmvuln(pkg:"nss-pam-ldapd", rpm:"nss-pam-ldapd~0.7.5~18.1.el6_4", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
