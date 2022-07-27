###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for luci CESA-2014:1194 centos5
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.882048");
  script_version("$Revision: 14222 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-10-01 17:00:09 +0530 (Wed, 01 Oct 2014)");
  script_cve_id("CVE-2012-5485", "CVE-2012-5486", "CVE-2012-5488", "CVE-2012-5497",
                "CVE-2012-5498", "CVE-2012-5499", "CVE-2012-5500", "CVE-2013-6496",
                "CVE-2014-3521");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CentOS Update for luci CESA-2014:1194 centos5");
  script_tag(name:"insight", value:"The Conga project is a management system for remote workstations.
It consists of luci, which is a secure web-based front end, and ricci,
which is a secure daemon that dispatches incoming messages to underlying
management modules.

It was discovered that Plone, included as a part of luci, did not properly
protect the administrator interface (control panel). A remote attacker
could use this flaw to inject a specially crafted Python statement or
script into Plone's restricted Python sandbox that, when the administrator
interface was accessed, would be executed with the privileges of that
administrator user. (CVE-2012-5485)

It was discovered that Plone, included as a part of luci, did not properly
sanitize HTTP headers provided within certain URL requests. A remote
attacker could use a specially crafted URL that, when processed, would
cause the injected HTTP headers to be returned as a part of the Plone HTTP
response, potentially allowing the attacker to perform other more advanced
attacks. (CVE-2012-5486)

Multiple information leak flaws were found in the way conga processed luci
site extension-related URL requests. A remote, unauthenticated attacker
could issue a specially crafted HTTP request that, when processed, would
result in unauthorized information disclosure. (CVE-2013-6496)

It was discovered that various components in the luci site
extension-related URLs were not properly restricted to administrative
users. A remote, authenticated attacker could escalate their privileges to
perform certain actions that should be restricted to administrative users,
such as adding users and systems, and viewing log data. (CVE-2014-3521)

It was discovered that Plone, included as a part of luci, did not properly
protect the privilege of running RestrictedPython scripts. A remote
attacker could use a specially crafted URL that, when processed, would
allow the attacker to submit and perform expensive computations or, in
conjunction with other attacks, be able to access or alter privileged
information. (CVE-2012-5488)

It was discovered that Plone, included as a part of luci, did not properly
enforce permissions checks on the membership database. A remote attacker
could use a specially crafted URL that, when processed, could allow the
attacker to enumerate user account names. (CVE-2012-5497)

It was discovered that Plone, included as a part of luci, did not properly
handle the processing of requests for certain collections. A remote
attacker could use a specially crafted URL that, when processed, would lead
to excessive I/O and/or cache resource consumption. (CVE-2012-5498)

It was discovered that Plone, included ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"luci on CentOS 5");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://lists.centos.org/pipermail/centos-announce/2014-September/020611.html");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'luci'
  package(s) announced via the referenced advisory.");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS5");
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

  if ((res = isrpmvuln(pkg:"luci", rpm:"luci~0.12.2~81.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"ricci", rpm:"ricci~0.12.2~81.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"conga", rpm:"conga~0.12.2~81.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}
