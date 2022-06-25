###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for finch CESA-2008:1023 centos4 i386
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
tag_insight = "Pidgin is a multi-protocol Internet Messaging client.

  A denial-of-service flaw was found in Pidgin's MSN protocol handler. If a
  remote user was able to send, and the Pidgin user accepted, a
  carefully-crafted file request, it could result in Pidgin crashing.
  (CVE-2008-2955)
  
  A denial-of-service flaw was found in Pidgin's Universal Plug and Play
  (UPnP) request handling. A malicious UPnP server could send a request to
  Pidgin, causing it to download an excessive amount of data, consuming all
  available memory or disk space. (CVE-2008-2957)
  
  A flaw was found in the way Pidgin handled SSL certificates. The NSS SSL
  implementation in Pidgin did not properly verify the authenticity of SSL
  certificates. This could have resulted in users unknowingly connecting to a
  malicious SSL service. (CVE-2008-3532)
  
  In addition, this update upgrades pidgin from version 2.3.1 to version
  2.5.2, with many additional stability and functionality fixes from the
  Pidgin Project.
  
  Note: the Secure Internet Live Conferencing (SILC) chat network protocol
  has recently changed, affecting all versions of pidgin shipped with Red Hat
  Enterprise Linux.
  
  Pidgin cannot currently connect to the latest version of the SILC server
  (1.1.14): it fails to properly exchange keys during initial login. This
  update does not correct this. Red Hat Bugzilla #474212 (linked to in the
  References section) has more information.
  
  Note: after the errata packages are installed, Pidgin must be restarted for
  the update to take effect.
  
  All Pidgin users should upgrade to these updated packages, which contains
  Pidgin version 2.5.2 and resolves these issues.";

tag_affected = "finch on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-December/015512.html");
  script_oid("1.3.6.1.4.1.25623.1.0.315148");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 08:36:45 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2008-2955", "CVE-2008-2957", "CVE-2008-3532");
  script_name( "CentOS Update for finch CESA-2008:1023 centos4 i386");

  script_tag(name:"summary", value:"Check for the Version of finch");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
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

  if ((res = isrpmvuln(pkg:"finch", rpm:"finch~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"finch-devel", rpm:"finch-devel~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple", rpm:"libpurple~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-devel", rpm:"libpurple-devel~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-perl", rpm:"libpurple-perl~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libpurple-tcl", rpm:"libpurple-tcl~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-devel", rpm:"pidgin-devel~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"pidgin-perl", rpm:"pidgin-perl~2.5.2~6.el4", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
