###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gdm CESA-2010:0657 centos4 i386
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
tag_insight = "The GNOME Display Manager (GDM) is a configurable re-implementation of XDM,
  the X Display Manager. GDM allows you to log in to your system with the X
  Window System running, and supports running several different X sessions on
  your local machine at the same time.

  A flaw was found in the way the gdm package was built. The gdm package was
  missing TCP wrappers support on 64-bit platforms, which could result in an
  administrator believing they had access restrictions enabled when they did
  not. (CVE-2007-5079)
  
  This update also fixes the following bug:
  
  * sometimes the system would hang instead of properly shutting down when
  a user chose &quot;Shut down&quot; from the login screen. (BZ#625818)
  
  All users should upgrade to this updated package, which contains backported
  patches to correct these issues. GDM must be restarted for this update to
  take effect. Rebooting achieves this, but changing the runlevel from 5 to 3
  and back to 5 also restarts GDM.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "gdm on CentOS 4";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2010-August/016948.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313945");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-30 16:59:25 +0200 (Mon, 30 Aug 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2007-5079");
  script_name("CentOS Update for gdm CESA-2010:0657 centos4 i386");

  script_tag(name: "summary" , value: "Check for the Version of gdm");
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

if(release == "CentOS4")
{

  if ((res = isrpmvuln(pkg:"gdm", rpm:"gdm~2.6.0.5~7.rhel4.19.el4_8.2", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
