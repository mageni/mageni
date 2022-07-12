###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_CESA-2018_0223_nautilus_centos7.nasl 14058 2019-03-08 13:25:52Z cfischer $
#
# CentOS Update for nautilus CESA-2018:0223 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882839");
  script_version("$Revision: 14058 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-26 07:46:43 +0100 (Fri, 26 Jan 2018)");
  script_cve_id("CVE-2017-14604");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for nautilus CESA-2018:0223 centos7");
  script_tag(name:"summary", value:"Check the version of nautilus");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Nautilus is the file manager and graphical
shell for the GNOME desktop.

Security Fix(es):

  * An untrusted .desktop file with executable permission set could choose
its displayed name and icon, and execute commands without warning when
opened by the user. An attacker could use this flaw to trick a user into
opening a .desktop file disguised as a document, such as a PDF, and execute
arbitrary commands. (CVE-2017-14604)

Note: This update will change the behavior of Nautilus. Nautilus will now
prompt the user for confirmation when executing an untrusted .desktop file
for the first time, and then add it to the trusted file list. Desktop files
stored in the system directory, as specified by the XDG_DATA_DIRS
environment variable, are always considered trusted and executed without
prompt.");
  script_tag(name:"affected", value:"nautilus on CentOS 7");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2018-January/022734.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";

if(release == "CentOS7")
{

  if ((res = isrpmvuln(pkg:"nautilus", rpm:"nautilus~3.22.3~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nautilus-devel", rpm:"nautilus-devel~3.22.3~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"nautilus-extensions", rpm:"nautilus-extensions~3.22.3~4.el7_4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
