###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for nspluginwrapper CESA-2012:1459 centos6
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2012-November/018992.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881536");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-11-15 11:42:30 +0530 (Thu, 15 Nov 2012)");
  script_cve_id("CVE-2011-2486");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("CentOS Update for nspluginwrapper CESA-2012:1459 centos6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nspluginwrapper'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS6");
  script_tag(name:"affected", value:"nspluginwrapper on CentOS 6");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"insight", value:"nspluginwrapper is a utility which allows 32-bit plug-ins to run in a
  64-bit browser environment (a common example is Adobe's browser plug-in for
  presenting proprietary Flash files embedded in web pages). It includes the
  plug-in viewer and a tool for managing plug-in installations and updates.

  It was not possible for plug-ins wrapped by nspluginwrapper to discover
  whether the browser was running in Private Browsing mode. This flaw could
  lead to plug-ins wrapped by nspluginwrapper using normal mode while they
  were expected to run in Private Browsing mode. (CVE-2011-2486)

  This update also fixes the following bug:

  * When using the Adobe Reader web browser plug-in provided by the
  acroread-plugin package on a 64-bit system, opening Portable Document
  Format (PDF) files in Firefox could cause the plug-in to crash and a black
  window to be displayed where the PDF should be. Firefox had to be restarted
  to resolve the issue. This update implements a workaround in
  nspluginwrapper to automatically handle the plug-in crash, so that users
  no longer have to keep restarting Firefox. (BZ#869554)

  All users of nspluginwrapper are advised to upgrade to these updated
  packages, which upgrade nspluginwrapper to upstream version 1.4.4, and
  correct these issues. After installing the update, Firefox must be
  restarted for the changes to take effect.");
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

  if ((res = isrpmvuln(pkg:"nspluginwrapper", rpm:"nspluginwrapper~1.4.4~1.el6_3", rls:"CentOS6")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
