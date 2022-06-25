###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for samba CESA-2010:0697 centos3 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "Samba is a suite of programs used by machines to share files, printers, and
  other information.

  A missing array boundary checking flaw was found in the way Samba parsed
  the binary representation of Windows security identifiers (SIDs). A
  malicious client could send a specially-crafted SMB request to the Samba
  server, resulting in arbitrary code execution with the privileges of the
  Samba server (smbd). (CVE-2010-3069)

  For Red Hat Enterprise Linux 4, this update also fixes the following bug:

  * Previously, the restorecon utility was required during the installation
  of the samba-common package. As a result, attempting to update samba
  without this utility installed may have failed with the following error:

  /var/tmp/rpm-tmp.[xxxxx]: line 7: restorecon: command not found

  With this update, the utility is only used when it is already present on
  the system, and the package is now always updated as expected. (BZ#629602)

  Users of Samba are advised to upgrade to these updated packages, which
  correct these issues. After installing this update, the smb service will be
  restarted automatically.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "samba on CentOS 3";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-September/016996.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314946");
  script_version("$Revision: 8228 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-22 08:29:52 +0100 (Fri, 22 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-09-22 08:32:53 +0200 (Wed, 22 Sep 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-3069");
  script_name("CentOS Update for samba CESA-2010:0697 centos3 i386");

  script_tag(name: "summary" , value: "Check for the Version of samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS3")
{

  if ((res = isrpmvuln(pkg:"samba", rpm:"samba~3.0.9~1.3E.18", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-client", rpm:"samba-client~3.0.9~1.3E.18", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-common", rpm:"samba-common~3.0.9~1.3E.18", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"samba-swat", rpm:"samba-swat~3.0.9~1.3E.18", rls:"CentOS3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
