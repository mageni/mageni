###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for USB Drivers and Framework 115553-29
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

tag_affected = "USB Drivers and Framework on solaris_5.9_sparc";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  USB Drivers and Framework
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309579");
  script_version("$Revision: 5359 $");
  script_cve_id("CVE-2008-0718");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 12:20:19 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-06-03 12:28:12 +0200 (Wed, 03 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_name( "Solaris Update for USB Drivers and Framework 115553-29");

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-115553-29-1");

  script_tag(name:"summary", value:"Check for the Version of USB Drivers and Framework");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Solaris Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/solosversion");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("solaris.inc");

release = get_kb_item("ssh/login/solosversion");

if(release == NULL){
  exit(0);
}

if(solaris_check_patch(release:"5.9", arch:"sparc", patch:"115553-29", package:"SUNWcar.us SUNWmdb SUNWcpr.u SUNWcsl SUNWcprx.us SUNWkey SUNWusbx SUNWcprx.u SUNWcsxu SUNWcarx.us SUNWusbu SUNWmdbx SUNWcpr.us SUNWusb SUNWcpr.m SUNWhea SUNWcslx SUNWcstlx SUNWcarx.u SUNWcsu SUNWcar.u SUNWcstl") < 0)
{
  security_message(0);
  exit(0);
}
