###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for kernel update  and Apache 108528-29
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

tag_affected = "kernel update  and Apache on solaris_5.8_sparc";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  kernel update  and Apache
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.308677");
  script_version("$Revision: 5359 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 12:20:19 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-06-03 12:37:58 +0200 (Wed, 03 Jun 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name( "Solaris Update for kernel update  and Apache 108528-29");

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-108528-29-1");

  script_tag(name:"summary", value:"Check for the Version of kernel update  and Apache");
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

if(solaris_check_patch(release:"5.8", arch:"sparc", patch:"108528-29", package:"SUNWapchS SUNWcar.us SUNWncaux SUNWpmux SUNWpmu SUNWpiclh SUNWarc SUNWscpu SUNWcar.d SUNWpiclx SUNWcar.m SUNWidn.u SUNWmdb SUNWwrsmx.u SUNWncar SUNWcpr.u SUNWapchr SUNWkvm.u SUNWcpcx.us SUNWncarx SUNWkvmx.u SUNWkvm.us FJSVhea SUNWarcx SUNWcsl SUNWkvmx.us SUNWusx.u SUNWefcx.u SUNWcprx.us FJSVmdbx SUNWdrr.u FJSVpiclu SUNWdrrx.us SUNWwrsdx.u SUNWcprx.u SUNWcsxu SUNWcarx.us SUNWpiclu SUNWmdbx FJSVvplr.us SUNWcpr.us SUNWdrr.us SUNWcsr SUNWwrsux.u SUNWfruid SUNWncau SUNWtnfc SUNWcpcx.u FJSVmdb SUNWcpr.m SUNWhea SUNWpmr SUNWcslx SUNWcpc.us SUNWcstlx SUNWapchd SUNWcarx.u FJSVvplu.us SUNWcsu SUNWcar.u SUNWdrrx.u SUNWsrh SUNWfruip.u SUNWapchu SUNWidnx.u SUNWcpc.u SUNWfruix SUNWcstl SUNWtnfcx") < 0)
{
  security_message(0);
  exit(0);
}
