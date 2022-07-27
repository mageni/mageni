###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for pidgin FEDORA-2010-17130
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
tag_insight = "Pidgin allows you to talk to anyone using a variety of messaging
  protocols including AIM, MSN, Yahoo!, Jabber, Bonjour, Gadu-Gadu,
  ICQ, IRC, Novell Groupwise, QQ, Lotus Sametime, SILC, Simple and
  Zephyr.  These protocols are implemented using a modular, easy to
  use design.  To use a protocol, just add an account using the
  account editor.

  Pidgin supports many common features of other clients, as well as many
  unique features, such as perl scripting, TCL scripting and C plugins.
  
  Pidgin is not affiliated with or endorsed by America Online, Inc.,
  Microsoft Corporation, Yahoo! Inc., or ICQ Inc.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "pidgin on Fedora 12";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-November/050695.html");
  script_oid("1.3.6.1.4.1.25623.1.0.313658");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-11-16 14:49:48 +0100 (Tue, 16 Nov 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_xref(name: "FEDORA", value: "2010-17130");
  script_cve_id("CVE-2010-3711", "CVE-2010-2528", "CVE-2010-1624", "CVE-2010-0277", "CVE-2010-0420", "CVE-2010-0423", "CVE-2010-0013");
  script_name("Fedora Update for pidgin FEDORA-2010-17130");

  script_tag(name: "summary" , value: "Check for the Version of pidgin");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
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

if(release == "FC12")
{

  if ((res = isrpmvuln(pkg:"pidgin", rpm:"pidgin~2.7.5~1.fc12", rls:"FC12")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
