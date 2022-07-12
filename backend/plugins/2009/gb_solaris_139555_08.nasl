###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for Kernel 139555-08
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

tag_affected = "Kernel on solaris_5.10_sparc";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  Kernel
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.311630");
  script_version("$Revision: 5359 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 12:20:19 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-06-03 12:34:39 +0200 (Wed, 03 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2008-5077");
  script_name( "Solaris Update for Kernel 139555-08");

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-139555-08-1");

  script_tag(name:"summary", value:"Check for the Version of Kernel");
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

if(solaris_check_patch(release:"5.10", arch:"sparc", patch:"139555-08", package:"SUNWcakr.u SUNWsshcu SUNWudaplu SUNWdhcsu SUNWopenssl-include SUNWudapltu SUNWrds SUNWarc SUNWiscsitgtr SUNWipfu SUNWfmd SUNWbtool SUNWidn.u FJSVcpcu SUNWperl584core SUNWcry SUNWsckmu.u SUNWsmapi SUNWtavor SUNWopenssl-commands SUNWipfh SUNWmdb SUNWzfsu SUNWldomr.v SUNWcakr.us SUNWsshdu SUNWcart200.v SUNWkvm.u SUNWnfssu SUNWmdr SUNWkvm.v SUNWkvm.us FJSVhea SUNWpool SUNWibsdpib SUNWxcu4 SUNWdtrc SUNWs8brandr SUNWopenssl-libraries FJSVfmd SUNWus.u SUNWcsl FJSVmdbr SUNWcpcu SUNWiscsitgtu SUNWib SUNWtoo SUNWsckmr FJSVpiclu SUNWdmgtu SUNWkvmt200.v SUNWpiclu SUNWfmdr SUNWcakr.v SUNWs9brandr SUNWzfsr SUNWroute SUNWckr SUNWcsr SUNWefcl SUNWcvcr.u SUNWmdbr SUNWpd SUNWzfskr SUNWncau SUNWarcr SUNWmdu FJSVmdb SUNWwbsup SUNWhea SUNWnfsckr SUNWdtrp SUNWpl5u SUNWcslr SUNWsshu SUNWdcsr SUNWcsu SUNWust1.v SUNWnxge.v SUNWesu SUNWnxge.u SUNWcsd SUNWhermon SUNWfruip.u SUNWssad SUNWpdu SUNWloc SUNWzoneu SUNWust2.v SUNWudfr") < 0)
{
  security_message(0);
  exit(0);
}