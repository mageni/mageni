###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for thunderbird CESA-2010:0545 centos5 i386
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
  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2010-July/016820.html");
  script_oid("1.3.6.1.4.1.25623.1.0.880600");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2011-08-09 08:20:34 +0200 (Tue, 09 Aug 2011)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-0174", "CVE-2010-0175", "CVE-2010-0176", "CVE-2010-0177", "CVE-2010-1197", "CVE-2010-1198", "CVE-2010-1199", "CVE-2010-1200", "CVE-2010-1205", "CVE-2010-1211", "CVE-2010-1214", "CVE-2010-2753", "CVE-2010-2754");
  script_name("CentOS Update for thunderbird CESA-2010:0545 centos5 i386");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
  script_tag(name:"affected", value:"thunderbird on CentOS 5");
  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

  A memory corruption flaw was found in the way Thunderbird decoded certain
  PNG images. An attacker could create a mail message containing a
  specially-crafted PNG image that, when opened, could cause Thunderbird to
  crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2010-1205)

  Several flaws were found in the processing of malformed HTML mail content.
  An HTML mail message containing malicious content could cause Thunderbird
  to crash or, potentially, execute arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2010-0174, CVE-2010-1200, CVE-2010-1211,
  CVE-2010-1214, CVE-2010-2753)

  An integer overflow flaw was found in the processing of malformed HTML mail
  content. An HTML mail message containing malicious content could cause
  Thunderbird to crash or, potentially, execute arbitrary code with the
  privileges of the user running Thunderbird. (CVE-2010-1199)

  Several use-after-free flaws were found in Thunderbird. Viewing an HTML
  mail message containing malicious content could result in Thunderbird
  executing arbitrary code with the privileges of the user running
  Thunderbird. (CVE-2010-0175, CVE-2010-0176, CVE-2010-0177)

  A flaw was found in the way Thunderbird plug-ins interact. It was possible
  for a plug-in to reference the freed memory from a different plug-in,
  resulting in the execution of arbitrary code with the privileges of the
  user running Thunderbird. (CVE-2010-1198)

  A flaw was found in the way Thunderbird handled the 'Content-Disposition:
  attachment' HTTP header when the 'Content-Type: multipart' HTTP header was
  also present. Loading remote HTTP content that allows arbitrary uploads and
  relies on the 'Content-Disposition: attachment' HTTP header to prevent
  content from being displayed inline, could be used by an attacker to serve
  malicious content to users. (CVE-2010-1197)

  A same-origin policy bypass flaw was found in Thunderbird. Remote HTML
  content could steal private data from different remote HTML content
  Thunderbird has loaded. (CVE-2010-2754)

  All Thunderbird users should upgrade to this updated package, which
  resolves these issues. All running instances of Thunderbird must be
  restarted for the update to take effect.");
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

  if ((res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~2.0.0.24~6.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
