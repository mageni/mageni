###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for wireshark CESA-2008:0890 centos4 x86_64
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
tag_insight = "Wireshark is a program for monitoring network traffic. Wireshark was
  previously known as Ethereal.

  Multiple buffer overflow flaws were found in Wireshark. If Wireshark read
  a malformed packet off a network, it could crash or, possibly, execute
  arbitrary code as the user running Wireshark. (CVE-2008-3146)
  
  Several denial of service flaws were found in Wireshark. Wireshark could
  crash or stop responding if it read a malformed packet off a network, or
  opened a malformed dump file. (CVE-2008-1070, CVE-2008-1071, CVE-2008-1072,
  CVE-2008-1561, CVE-2008-1562, CVE-2008-1563, CVE-2008-3137, CVE-2008-3138,
  CVE-2008-3141, CVE-2008-3145, CVE-2008-3932, CVE-2008-3933, CVE-2008-3934)
  
  Additionally, this update changes the default Pluggable Authentication
  Modules (PAM) configuration to always prompt for the root password before
  each start of Wireshark. This avoids unintentionally running Wireshark with
  root privileges.
  
  Users of wireshark should upgrade to these updated packages, which contain
  Wireshark version 1.0.3, and resolve these issues.";

tag_affected = "wireshark on CentOS 4";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2008-October/015298.html");
  script_oid("1.3.6.1.4.1.25623.1.0.308166");
  script_version("$Revision: 6651 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-10 13:45:21 +0200 (Mon, 10 Jul 2017) $");
  script_tag(name:"creation_date", value:"2009-02-27 09:02:20 +0100 (Fri, 27 Feb 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1070", "CVE-2008-1071", "CVE-2008-1072", "CVE-2008-1561", "CVE-2008-1562", "CVE-2008-1563", "CVE-2008-3137", "CVE-2008-3138", "CVE-2008-3141", "CVE-2008-3145", "CVE-2008-3146", "CVE-2008-3932", "CVE-2008-3933", "CVE-2008-3934");
  script_name( "CentOS Update for wireshark CESA-2008:0890 centos4 x86_64");

  script_tag(name:"summary", value:"Check for the Version of wireshark");
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

  if ((res = isrpmvuln(pkg:"wireshark", rpm:"wireshark~1.0.3~3.el4_7", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"wireshark-gnome", rpm:"wireshark-gnome~1.0.3~3.el4_7", rls:"CentOS4")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
