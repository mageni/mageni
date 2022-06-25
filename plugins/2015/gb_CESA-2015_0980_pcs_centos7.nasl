###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for pcs CESA-2015:0980 centos7
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
  script_oid("1.3.6.1.4.1.25623.1.0.882178");
  script_version("$Revision: 14058 $");
  script_cve_id("CVE-2015-1848");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-03-08 14:25:52 +0100 (Fri, 08 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-09 11:02:34 +0200 (Tue, 09 Jun 2015)");
  script_tag(name:"qod_type", value:"package");
  script_name("CentOS Update for pcs CESA-2015:0980 centos7");
  script_tag(name:"summary", value:"Check the version of pcs");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The pcs packages provide a command-line
  tool and a web UI to configure and manage the Pacemaker and Corosync tools.

It was found that the pcs daemon did not sign cookies containing session
data that were sent to clients connecting via the pcsd web UI. A remote
attacker could use this flaw to forge cookies and bypass authorization
checks, possibly gaining elevated privileges in the pcsd web UI.
(CVE-2015-1848)

This issue was discovered by Tomas Jelinek of Red Hat.

This update also fixes the following bug:

  * Previously, the Corosync tool allowed the two_node option and the
auto_tie_breaker option to exist in the corosync.conf file at the same
time. As a consequence, if both options were included, auto_tie_breaker was
silently ignored and the two_node fence race decided which node would
survive in the event of a communication break. With this update, the pcs
daemon has been fixed so that it does not produce corosync.conf files with
both two_node and auto_tie_breaker included. In addition, if both two_node
and auto_tie_breaker are detected in corosync.conf, Corosync issues a
message at start-up and disables two_node mode. As a result,
auto_tie_breaker effectively overrides two_node mode if both options are
specified. (BZ#1205848)

All pcs users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing the
updated packages, the pcsd daemon will be restarted automatically.");
  script_tag(name:"affected", value:"pcs on CentOS 7");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2015-May/021126.html");
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

  if ((res = isrpmvuln(pkg:"pcs", rpm:"pcs~0.9.137~13.el7_1.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"python-clufter", rpm:"python-clufter~0.9.137~13.el7_1.2", rls:"CentOS7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
