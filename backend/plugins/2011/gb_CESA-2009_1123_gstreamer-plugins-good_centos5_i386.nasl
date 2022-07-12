###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for gstreamer-plugins-good CESA-2009:1123 centos5 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2009-June/016005.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880798");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1932");
  script_name("CentOS Update for gstreamer-plugins-good CESA-2009:1123 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer-plugins-good'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"gstreamer-plugins-good on CentOS 5");
  script_tag(name:"insight", value:"GStreamer is a streaming media framework, based on graphs of filters which
  operate on media data. GStreamer Good Plug-ins is a collection of
  well-supported, good quality GStreamer plug-ins.

  Multiple integer overflow flaws, that could lead to a buffer overflow, were
  found in the GStreamer Good Plug-ins PNG decoding handler. An attacker
  could create a specially-crafted PNG file that would cause an application
  using the GStreamer Good Plug-ins library to crash or, potentially, execute
  arbitrary code as the user running the application when parsed.
  (CVE-2009-1932)

  All users of gstreamer-plugins-good are advised to upgrade to these updated
  packages, which contain a backported patch to correct these issues. After
  installing the update, all applications using GStreamer Good Plug-ins (such
  as some media playing applications) must be restarted for the changes to
  take effect.");
  script_tag(name:"solution", value:"Please install the updated packages.");
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

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-good", rpm:"gstreamer-plugins-good~0.10.9~1.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"gstreamer-plugins-good-devel", rpm:"gstreamer-plugins-good-devel~0.10.9~1.el5_3.2", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
