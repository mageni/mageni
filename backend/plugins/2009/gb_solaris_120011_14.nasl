###############################################################################
# OpenVAS Vulnerability Test
#
# Solaris Update for kernel 120011-14
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

tag_affected = "kernel on solaris_5.10_sparc";
tag_insight = "The remote host is missing a patch containing a security fix,
  which affects the following component(s): 
  kernel
  For more information please visit the below reference link.";
tag_solution = "Please Install the Updated Packages.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.309501");
  script_version("$Revision: 5359 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 12:20:19 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-06-03 12:31:50 +0200 (Wed, 03 Jun 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2006-3738", "CVE-2006-4343", "CVE-2006-4339", "CVE-2006-2937", "CVE-2006-2940", "CVE-2007-0957", "CVE-2006-0225", "CVE-2005-2969");
  script_name( "Solaris Update for kernel 120011-14");

  script_xref(name : "URL" , value : "http://sunsolve.sun.com/search/document.do?assetkey=1-21-120011-14-1");

  script_tag(name:"summary", value:"Check for the Version of kernel");
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

if(solaris_check_patch(release:"5.10", arch:"sparc", patch:"120011-14", package:"SUNWcakr.u SUNWsshcu SUNWpcmci SUNWcnetr SUNWcar.us SUNWdhcsu SUNWrcmdc SUNWperl584usr SUNWixgb SUNWpsu SUNWfss SUNWatfsu SUNWopenssl-include SUNWpmu SUNWlldap SUNWipfr SUNWudapltu SUNWzoner SUNWarc SUNWipfu SUNWfmd SUNWintgige SUNWscpu SUNWbtool SUNWxge SUNWidn.u SUNWsra FJSVcpcu SUNWperl584core SUNWbart SUNWkrbu SUNWdrcr.u SUNWsmapi SUNWtavor SUNWbcp SUNWipfh SUNWmdb SUNWzfsu SUNWsndmr SUNWaudit SUNWncar SUNWldomr.v SUNWiopc.v SUNWcakr.us SUNWpapi SUNWsshdu SUNWcart200.v SUNWcpr.u SUNWkvm.u SUNWsndmu SUNWpppdu SUNWnfssu SUNWdhcm SUNWkdcu SUNWmdr SUNWkvm.v SUNWkvm.us FJSVhea SUNWpool SUNWxcu4 SUNWudapltr SUNWdtrc SUNWopenssl-libraries SUNWus.u SUNWcsl FJSVmdbr SUNWcpcu SUNWses SUNWsadmi SUNWvolu SUNWcpc.v SUNWib SUNWkey SUNWnisu SUNWtoo SUNWsckmr SUNWdrr.u FJSVpiclu SUNWdmgtu SUNWkvmt200.v SUNWusbu SUNWefc.u SUNWpiclu SUNWypu SUNWpoolr SUNWftduu SUNWppm SUNWuksp SUNWcakr.v SUNWslpu SUNWusb SUNWcti2.u SUNWzfsr SUNWdrr.us SUNWroute SUNWckr SUNWcsr SUNWdoc SUNWefcr SUNWaudh SUNWefcl SUNWrge SUNWtecla SUNWmdbr SUNWldomu.v SUNWpcu SUNWdscpr.u SUNWzfskr SUNWarcr SUNWmdu SUNWdcsu SUNWrcapu FJSVmdb SUNWwbsup SUNWcar.v SUNWhea SUNWqos SUNWntpu SUNWnfsckr SUNWdtrp SUNWcpc.us SUNWpl5u SUNWlibsasl SUNWcslr SUNWippcore SUNWsshu SUNWdcsr SUNWcsu SUNWust1.v SUNWcar.u SUNWnfscu SUNWesu SUNWcsd SUNWfruip.u SUNWssad SUNWcpc.u SUNWipplr SUNWpsm-lpd SUNWuprl SUNWefc.us SUNWzoneu SUNWipplu SUNWrcapr SUNWdfbh SUNWwrsm.u SUNWftdur SUNWerid SUNWauda") < 0)
{
  security_message(0);
  exit(0);
}
