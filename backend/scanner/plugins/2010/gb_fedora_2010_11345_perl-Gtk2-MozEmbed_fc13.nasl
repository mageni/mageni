###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for perl-Gtk2-MozEmbed FEDORA-2010-11345
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
tag_affected = "perl-Gtk2-MozEmbed on Fedora 13";
tag_insight = "This module allows you to use the Mozilla embedding widget from Perl.";
tag_solution = "Please Install the Updated Packages.";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2010-July/044453.html");
  script_oid("1.3.6.1.4.1.25623.1.0.314189");
  script_version("$Revision: 8528 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-07-23 16:10:25 +0200 (Fri, 23 Jul 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_xref(name: "FEDORA", value: "2010-11345");
  script_cve_id("CVE-2010-1211", "CVE-2010-1212", "CVE-2010-1208", "CVE-2010-1209", "CVE-2010-1214", "CVE-2010-1215", "CVE-2010-2752", "CVE-2010-2753", "CVE-2010-1205", "CVE-2010-1213", "CVE-2010-1207", "CVE-2010-1210", "CVE-2010-1206", "CVE-2010-2751", "CVE-2010-0654", "CVE-2010-2754");
  script_name("Fedora Update for perl-Gtk2-MozEmbed FEDORA-2010-11345");

  script_tag(name: "summary" , value: "Check for the Version of perl-Gtk2-MozEmbed");
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

if(release == "FC13")
{

  if ((res = isrpmvuln(pkg:"perl-Gtk2-MozEmbed", rpm:"perl-Gtk2-MozEmbed~0.08~6.fc13.15", rls:"FC13")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
