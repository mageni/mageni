###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_justsystems_ichitaro_prdts_dos_vuln.nasl 14335 2019-03-19 14:46:57Z asteins $
#
# JustSystems Ichitaro Products Denial Of Service Vulnerability.
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800544");
  script_version("$Revision: 14335 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 15:46:57 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1054");
  script_bugtraq_id(34138);
  script_name("JustSystems Ichitaro Products Denial Of Service Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34405/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49280");
  script_xref(name:"URL", value:"http://www.symantec.com/business/security_response/writeup.jsp?docid=2009-031608-2424-99");
  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js09001.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ichitaro_or_Viewer/Installed");
  script_tag(name:"impact", value:"This issue is widely exploited by Trojan.Tarodrop.H, a Trojan horse that
  drops several files on to the compromised system leading to arbitrary
  code execution and also crashing of the application.");
  script_tag(name:"affected", value:"JustSystems Ichitaro 13, 2004 thruogh 2008,
  JustSystems Ichitaro viewer 5.1.5.0 on Windows.");
  script_tag(name:"insight", value:"JustSystems products leads to a memory corruption while handling malformed
  documents using Web PURAGUINBYUA.");
  script_tag(name:"summary", value:"This host has JustSystems Ichitaro products installed and
  is prone to a denial of service vulnerability.");
  script_tag(name:"solution", value:"Apply the referenced security patches.


  *****

  NOTE: Ignore this warning, if patch is applied already.

  *****");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

ichitaroVer = get_kb_item("Ichitaro/Ver");
if(ichitaroVer)
{
  if(version_in_range(version:ichitaroVer, test_version:"2004",
                                           test_version2:"2008")||
     ichitaroVer =~ "13")
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

viewerVer = get_kb_item("Ichitaro/Viewer/Ver");
if(viewerVer)
{
  if(version_is_less_equal(version:viewerVer, test_version:"19.0.1.0")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exit(99);
