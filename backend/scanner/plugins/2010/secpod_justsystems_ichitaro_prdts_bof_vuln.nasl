###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_justsystems_ichitaro_prdts_bof_vuln.nasl 14233 2019-03-16 13:32:43Z mmartin $
#
# JustSystems Ichitaro Products 'RTF' Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902041");
  script_version("$Revision: 14233 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-16 14:32:43 +0100 (Sat, 16 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-04-16 16:17:26 +0200 (Fri, 16 Apr 2010)");
  script_bugtraq_id(34403);
  script_cve_id("CVE-2009-4737");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("JustSystems Ichitaro Products 'RTF' Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"http://secunia.com/advisories/34611");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/49739");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0957");
  script_xref(name:"URL", value:"http://www.justsystems.com/jp/info/js09002.html");
  script_xref(name:"URL", value:"http://www.ichitaro.com");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_justsystems_ichitaro_prdts_detect.nasl");
  script_mandatory_keys("Ichitaro/Ichitaro_or_Viewer/Installed");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code on the
  vulnerable system or cause the application to crash.");
  script_tag(name:"affected", value:"JustSystems Ichitaro version 13, 2004 thruogh 2009,
  JustSystems Ichitaro viewer version 19.0.1.0 and prior");
  script_tag(name:"insight", value:"The flaw is due to improper bounds checking when opening the
  specially crafted RTF files.");
  script_tag(name:"summary", value:"This host is installed with JustSystems Ichitaro product(s) and is
  prone to buffer overflow vulnerability.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"Apply the patches or Upgrade to the recernt version of Ichitaro

  *****
  NOTE: Ignore this warning, if patch is applied already.
  *****");
  exit(0);
}


include("version_func.inc");

ichitaroVer = get_kb_item("Ichitaro/Ver");
if(ichitaroVer)
{
  if(version_in_range(version:ichitaroVer, test_version:"2004",
                                           test_version2:"2009")||
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
  }
}
