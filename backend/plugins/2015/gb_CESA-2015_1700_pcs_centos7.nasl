###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pcs CESA-2015:1700 centos7
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882267");
  script_version("$Revision: 14058 $");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-09-02 06:59:38 +0200 (Wed, 02 Sep 2015)");
  script_cve_id("CVE-2015-5189", "CVE-2015-5190");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for pcs CESA-2015:1700 centos7");
  script_tag(name:"summary", value:"Check the version of pcs");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The pcs packages provide a command-line configuration system for the
Pacemaker and Corosync utilities.

A command injection flaw was found in the pcsd web UI. An attacker able to
trick a victim that was logged in to the pcsd web UI into visiting a
specially crafted URL could use this flaw to execute arbitrary code with
root privileges on the server hosting the web UI. (CVE-2015-5190)

A race condition was found in the way the pcsd web UI backend performed
authorization of user requests. An attacker could use this flaw to send a
request that would be evaluated as originating from a different user,
potentially allowing the attacker to perform actions with permissions of a
more privileged user. (CVE-2015-5189)

These issues were discovered by Tom Jelnek of Red Hat.

All pcs users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"pcs on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-September/021363.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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

  if ((res = isrpmvuln(pkg:"pcs", rpm:"pcs~0.9.137~13.el7_1.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-clufter", rpm:"python-clufter~0.9.137~13.el7_1.4", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
